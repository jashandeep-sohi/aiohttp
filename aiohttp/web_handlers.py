import asyncio
import os
import stat
import mimetypes

from . import hdrs
from .web_reqrep import StreamResponse
from .web_exceptions import HTTPMethodNotAllowed, HTTPNotFound, HTTPNotModified

__all__ = ("DirHandler",)


class DirHandler(object):

    def __init__(self, base_dir, chunk_size=None, response_factory=None):
        self._base_dir = os.path.abspath(base_dir)
        self._chunk_size = chunk_size or 256 * 1024
        self._response_factory = response_factory or StreamResponse

        self._no_sendfile = (bool(os.environ.get("AIOHTTP_NOSENDFILE")) or
                             not hasattr(os, "sendfile"))

    def __repr__(self):
        return ("<DirHandler {base_dir:r} sendfile={sendfile} "
                "chunk_size={chunk_size}>").format(
            base_dir=self._basedir, sendfile=not self._no_sendfile,
            chunk_size=self._chunk_size)

    def __call__(self, req):
        method = req.method

        if method == "GET":
            return self.get(req)
        elif method == "HEAD":
            return self.head(req)
        else:
            raise HTTPMethodNotAllowed(method, ("HEAD", "GET"))

    def _validate_path(self, req):
        req_path = req.match.get("path", "")
        path = os.path.normpath(os.path.join(self._base_dir, req_path))

        # Directory traversal attack mitigation
        if not path.startswith(self._base_dir):
            raise HTTPNotFound()

        try:
            path_stat = os.stat(path)
        except FileNotFoundError:
            raise HTTPNotFound()

        return path, path_stat

    def _head(self, req, path, path_stat):
        if not stat.S_ISREG(path_stat):
            raise HTTPNotFound()

        mtime = path_stat.st_mtime
        modsince = req.if_modified_since
        if modsince is not None and mtime <= modsince.timestamp():
            raise HTTPNotModified()

        content_type, content_encoding = mimetypes.guess_type(path)

        resp = self._response_factory()
        resp.content_type = content_type or "application/octet-stream"
        if content_encoding:
            resp.headers[hdrs.CONTENT_ENCODING] = content_encoding
        resp.last_modified = mtime
        resp.content_length = path_stat.st_size

        return resp

    def _sendfile_system_cb(self, fut, out_fd, in_fd, offset, count, loop,
                            registered):
        if registered:
            loop.remove_writer(out_fd)
        try:
            n = os.sendfile(out_fd, in_fd, offset, count)
            if n == 0:  # EOF reached
                n = count
        except (BlockingIOError, InterruptedError):
            n = 0
        except Exception as exc:
            fut.set_exception(exc)
            return

        if n < count:
            loop.add_writer(out_fd, self._sendfile_system_cb, fut, out_fd,
                            in_fd, offset + n, count - n, loop, True)
        else:
            fut.set_result(None)

    @asyncio.coroutine
    def _sendfile_fallback(self, resp, fobj, count):
        chunk_size = self._chunk_size

        chunk = fobj.read(chunk_size)
        while chunk and count > chunk_size:
            resp.write(chunk)
            yield from resp.drain()
            count = count - chunk_size
            chunk = fobj.read(chunk_size)

        if chunk:
            resp.write(chunk[:count])
            yield from resp.drain()

    def _sendfile(self, req, resp, fobj, count):
        transport = req.transport
        sslcontext = transport.get_extra_info("sslcontext")
        socket = transport.get_extra_info("socket")

        if not socket or sslcontext or self._no_sendfile:
            yield from self._sendfile_fallback(resp, fobj, count)
        else:
            yield from resp.drain()
            loop = req.app.loop
            out_fd = socket.fileno()
            in_fd = fobj.fileno()
            fut = asyncio.Future(loop=loop)
            self._sendfile_system_cb(fut, out_fd, in_fd, 0, count, loop, False)
            yield from fut

    def head(self, req):
        path, path_stat = self._validate_path(req)
        return self._head(req, path, path_stat)

    @asyncio.coroutine
    def get(self, req):
        path, path_stat = self._validate_path(req)
        resp = self._head(req, path, path_stat)

        try:
            fobj = open(path, "rb")
        except FileNotFoundError:  # in case of race condition
            raise HTTPNotFound()
        else:
            yield from resp.prepare(req)
            yield from self._sendfile(req, resp, fobj, path_stat.st_size)
        finally:
            fobj.close()

        return resp
