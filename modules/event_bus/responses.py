"""
Response Executor (Redacted)
=============================
Automated response logic is intentionally removed.
"""


class ResponseExecutor:
    def __init__(self, *_, **__):
        self._handlers = {}
        self._socketio = None
        self._event_bus = None

    def set_socketio(self, socketio):
        self._socketio = socketio

    def set_event_bus(self, event_bus):
        self._event_bus = event_bus

    def register_handler(self, name, handler):
        self._handlers[name] = handler

    def execute(self, *_args, **_kwargs):
        return None


_GLOBAL_EXECUTOR: ResponseExecutor | None = None


def get_response_executor(event_bus=None, socketio=None) -> ResponseExecutor:
    global _GLOBAL_EXECUTOR
    if _GLOBAL_EXECUTOR is None:
        _GLOBAL_EXECUTOR = ResponseExecutor()
    if socketio:
        _GLOBAL_EXECUTOR.set_socketio(socketio)
    if event_bus:
        _GLOBAL_EXECUTOR.set_event_bus(event_bus)
    return _GLOBAL_EXECUTOR


__all__ = ['ResponseExecutor', 'get_response_executor']
