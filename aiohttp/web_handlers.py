import asyncio
import os
import stat
import mimetypes

from datetime import datetime
from . import hdrs
from .web_reqrep import StreamResponse
from .web_exceptions import HTTPMethodNotAllowed, HTTPNotFound, HTTPNotModified

__all__ = ("DirHandler", "FileHandler",)


class _FileHandlerMixin(object):

    def __init__(self, chunk_size=None):
        self._chunk_size = chunk_size or 1024 * 256

        self._no_sendfile = (bool(os.environ.get("AIOHTTP_NOSENDFILE")) or
                             not hasattr(os, "sendfile"))

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

    def _head_file(self, req, path, path_stat, response_factory):
        modsince = req.if_modified_since
        file_mtime = path_stat.st_mtime

        if modsince is not None and file_mtime <= modsince.timestamp():
            raise HTTPNotModified()

        content_type, content_encoding = mimetypes.guess_type(path)

        resp = response_factory()
        resp.content_type = content_type or "application/octet-stream"
        if content_encoding:
            resp.headers[hdrs.CONTENT_ENCODING] = content_encoding
        resp.last_modified = file_mtime
        resp.content_length = path_stat.st_size

        return resp

    @asyncio.coroutine
    def _get_file(self, req, path, path_stat, response_factory):
        resp = self._head_file(req, path, path_stat, response_factory)
        yield from resp.prepare(req)
        try:
            fobj = open(path, "rb")
        except FileNotFoundError:  # in case of a race condition
            raise HTTPNotFound()
        else:
            with fobj:
                yield from self._sendfile(req, resp, fobj, path_stat.st_size)

        return resp


class DirHandler(_FileHandlerMixin):

    def __init__(self, base_dir, index=True, chunk_size=None,
                 response_factory=None):
        self._base_dir = os.path.abspath(base_dir)
        self._index = index
        self._response_factory = response_factory or StreamResponse
        super().__init__(chunk_size)

    def __repr__(self):
        return ("<DirHandler {base_dir!r} index={index} sendfile={sendfile} "
                "chunk_size={chunk_size}>").format(
            base_dir=self._base_dir, sendfile=not self._no_sendfile,
            chunk_size=self._chunk_size, index=self._index)

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

        return req_path, path, path_stat

    def _head_index(self, req, dir_stat):
        modsince = req.if_modified_since
        dir_mtime = dir_stat.st_mtime

        if modsince is not None and dir_mtime <= modsince.timestamp():
            raise HTTPNotModified()

        resp = self._response_factory()
        resp.content_type = "text/html"
        resp.charset = "utf-8"
        resp.last_modified = dir_mtime

        return resp

    def _gen_index_html(self, req_path, dir_path):
        yield (
            """<!DOCTYPE><html lang="en">"""
            "<head>"
            """<meta charset="utf-8">"""
            "<title>%s</title>"
            "</head>"
            "<body>"
            "<h1>Index of /%r</h1>"
            "<hr>"
            """<table style="width:100%">"""
        ) % (req_path, req_path)

        yield "<tr><th>Name</th><th>Last Modified</th><th>Size</th></tr>"

        row_tmpl = (
            """<tr><td><a href="%s">%s</a></td>"""
            "<td>%s</td><td>%s</td></tr>"
        )

        for entry in sorted(os.listdir(dir_path)):
            try:
                entry_stat = os.stat(os.path.join(dir_path, entry))
            except FileNotFoundError:
                continue

            if stat.S_ISREG(entry_stat):
                size = entry_stat.st_size
            elif stat.S_ISDIR(entry_stat):
                size = "-"
            else:
                continue

            mtime = datetime.fromtimestamp(entry_stat.st_mtime)
            yield row_tmpl % (entry, entry, mtime, size)

        yield "</table><hr></body></html>"

    def head(self, req):
        req_path, path, path_stat = self._validate_path(req)

        if stat.S_ISREG(path_stat):
            resp = self._head_file(req, path, path_stat)
        elif self._index and stat.S_ISDIR(path_stat):
            resp = self._head_index(req, path_stat)
        else:
            raise HTTPNotFound()

        return resp

    @asyncio.coroutine
    def get(self, req):
        req_path, path, path_stat = self._validate_path(req)

        if stat.S_ISREG(path_stat):
            resp = yield from self._get_file(req, path, path_stat)
        elif self._index and stat.S_ISDIR(path_stat):
            resp = self._head_index(req, path_stat)
            body_gen = self._gen_index_html(req_path, path)
            body = "".join(body_gen).encode("utf-8")
            resp.content_length = len(body)

            yield from resp.prepare(req)
            resp.write(body)
        else:
            raise HTTPNotFound()

        return resp


class FileHandler(_FileHandlerMixin):

    def __init__(self, path, chunk_size=None, response_factory=None):
        self._path = os.path.abspath(path)
        self._response_factory = response_factory or StreamResponse
        super().__init__(chunk_size)

    def __repr__(self):
        return ("<FileHandler {path!r} sendfile={sendfile} "
                "chunk_size={chunk_size}>").format(
            path=self._path, sendfile=not self._no_sendfile,
            chunk_size=self._chunk_size)

    def __call__(self, req):
        method = req.method

        if method == "GET":
            return self.get(req)
        elif method == "HEAD":
            return self.head(req)
        else:
            raise HTTPMethodNotAllowed(method, ("HEAD", "GET"))

    def _check_path(self, path):
        try:
            path_stat = os.stat(path)
        except FileNotFoundError:
            raise HTTPNotFound()

        if not stat.S_ISREG(path_stat):
            raise HTTPNotFound()

        return path_stat

    def head(self, req):
        path = self._path
        path_stat = self._check_path(path)

        return self._head_file(req, path, path_stat, self._response_factory)

    @asyncio.coroutine
    def get(self, req):
        path = self._path
        path_stat = self._check_path(path)

        resp = yield from self._get_file(req, path, path_stat,
                                         self._response_factory)

        return resp
