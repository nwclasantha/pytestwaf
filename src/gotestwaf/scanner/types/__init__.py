"""Scanner type definitions."""

from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import ChromeDPTasks, GoHTTPRequest, Request
from gotestwaf.scanner.types.response import GoHTTPResponse, Response, ResponseMeta

__all__ = [
    "ChromeDPTasks",
    "GoHTTPRequest",
    "GoHTTPResponse",
    "HTTPClientType",
    "Request",
    "Response",
    "ResponseMeta",
]
