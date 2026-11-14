"""H11 protocol with a request-header timeout (uvicorn 0.54.0 does not time out idle or partial-header connections)."""
import h11
from uvicorn.protocols.http.h11_impl import H11Protocol

# Set by python -m gateway after the env is validated (seconds).
HEADER_TIMEOUT_S = 5


class HeaderTimeoutProtocol(H11Protocol):
    """Close the transport if request headers are not complete within HEADER_TIMEOUT_S.

    The timer is armed on connection_made and again after a keep-alive response, so the
    next request on the same connection has the same deadline. It is cancelled once a
    complete request line and headers have been parsed.
    """

    def connection_made(self, transport):
        super().connection_made(transport)
        self._arm_header_timer()

    def data_received(self, data):
        cycle_before = self.cycle
        try:
            super().data_received(data)
        except h11.LocalProtocolError as exc:
            # send_400_response after a response has started: h11 is MUST_CLOSE or
            # still in SEND_BODY (bad chunk arrived mid-stream).
            if not str(exc).startswith("can't handle event type Response"):
                raise
            # The error message names MUST_CLOSE / SEND_BODY / DONE, but h11
            # has already moved our_state to ERROR by the time we catch.
            if self.conn.our_state not in (h11.ERROR, h11.MUST_CLOSE, h11.SEND_BODY, h11.DONE):
                raise
            # The uvicorn.error filter already counted "Invalid HTTP request received."
            # as malformed once. Mark the cycle disconnected so the app's next
            # send does not raise "Can't send data when our state is ERROR".
            if self.cycle is not None:
                self.cycle.disconnected = True
            if self.transport is not None and not self.transport.is_closing():
                self.transport.close()
            return
        if self.cycle is not None and self.cycle is not cycle_before:
            self._cancel_header_timer()

    def on_response_complete(self):
        # super() may start the next pipelined RequestResponseCycle from already-buffered
        # headers; do not arm a timer that would then kill that request mid-body.
        cycle_before = self.cycle
        super().on_response_complete()
        if self.cycle is not None and self.cycle is not cycle_before:
            self._cancel_header_timer()
            return
        if self.transport is not None and not self.transport.is_closing():
            self._arm_header_timer()

    def connection_lost(self, exc):
        self._cancel_header_timer()
        super().connection_lost(exc)

    def _arm_header_timer(self):
        self._cancel_header_timer()
        self._header_timer = self.loop.call_later(HEADER_TIMEOUT_S, self._on_header_timeout)

    def _cancel_header_timer(self):
        timer = getattr(self, "_header_timer", None)
        if timer is not None:
            timer.cancel()
        self._header_timer = None

    def _on_header_timeout(self):
        self._header_timer = None
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()
