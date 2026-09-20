class IdaAssistantError(RuntimeError):
    """Base error returned by the scheduler."""


class QuotaExceeded(IdaAssistantError):
    pass


class SessionOwnershipError(IdaAssistantError):
    pass


class SampleBusy(IdaAssistantError):
    pass


class SourceChanged(IdaAssistantError):
    pass


class SourceOpenError(IdaAssistantError):
    pass


class SessionConflict(IdaAssistantError):
    pass


class SessionNotFound(IdaAssistantError):
    pass


class WorkerFailed(IdaAssistantError):
    pass


class WorkerTimedOut(WorkerFailed):
    pass


class AnalysisPending(IdaAssistantError):
    pass


class AnalysisFailed(IdaAssistantError):
    pass


class ToolFailed(IdaAssistantError):
    """The worker stayed healthy, but an IDA tool rejected the request."""


class UnsafeOperation(IdaAssistantError):
    pass
