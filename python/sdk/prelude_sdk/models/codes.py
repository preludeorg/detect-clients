import logging

from enum import Enum, EnumMeta


class MissingItem(EnumMeta):
    def __getitem__(cls, name):
        try:
            return super().__getitem__(name.upper())
        except (AttributeError, KeyError):
            try:
                return cls(int(name))
            except ValueError:
                return cls(name)


class RunCode(Enum, metaclass=MissingItem):
    INVALID = -1
    DAILY = 1
    WEEKLY = 2
    MONTHLY = 3
    SMART = 4
    DEBUG = 5
    RUN_ONCE = 6
    MONDAY = 10
    TUESDAY = 11
    WEDNESDAY = 12
    THURSDAY = 13
    FRIDAY = 14
    SATURDAY = 15
    SUNDAY = 16
    MONTH_1 = 20

    @classmethod
    def _missing_(cls, value):
        return RunCode.DAILY


class Mode(Enum, metaclass=MissingItem):
    MANUAL = 0
    FROZEN = 1
    AUTOPILOT = 2

    @classmethod
    def _missing_(cls, value):
        return Mode.MANUAL


class Permission(Enum, metaclass=MissingItem):
    INVALID = -1
    ADMIN = 0
    EXECUTIVE = 1
    BUILD = 2
    SERVICE = 3
    SUPPORT = 5

    @classmethod
    def _missing_(cls, value):
        return Permission.INVALID


class ExitCode(Enum):
    MISSING = -1
    UNKNOWN_ERROR = 1
    MALFORMED_TEST = 2
    UNREPORTED = 3
    PROCESS_BLOCKED = 9
    PROCESS_BLOCKED_GRACEFULLY = 15
    PROTECTED = 100
    UNPROTECTED = 101
    TIMED_OUT = 102
    FAILED_CLEANUP = 103
    TEST_NOT_RELEVANT = 104
    DYNAMIC_QUARANTINE = 105
    BLOCKED_AT_PERIMETER = 106
    EXPLOIT_PREVENTED = 107
    ENDPOINT_NOT_RELEVANT = 108
    INSUFFICIENT_PRIVILEGES = 109
    INCORRECTLY_BLOCKED = 110
    PREVENTED_EXECUTION = 126
    STATIC_QUARANTINE = 127
    BLOCKED = 137
    UNEXPECTED_ERROR = 256

    @classmethod
    def _missing_(cls, value):
        if value and not isinstance(value, int):
            return cls(int(value))
        logging.warning("Unknown ExitCode: %s", str(value))
        return ExitCode.MISSING

    @property
    def state(self):
        for k, v in State.mapping().items():
            if self in v:
                return k
        return State.NONE


class State(Enum):
    NONE = 0
    PROTECTED = 1
    UNPROTECTED = 2
    ERROR = 3
    NOT_RELEVANT = 4

    @classmethod
    def mapping(cls):
        return {
            State.ERROR: [
                ExitCode.FAILED_CLEANUP,
                ExitCode.INCORRECTLY_BLOCKED,
                ExitCode.MALFORMED_TEST,
                ExitCode.TIMED_OUT,
                ExitCode.UNEXPECTED_ERROR,
                ExitCode.UNKNOWN_ERROR,
                ExitCode.UNREPORTED,
            ],
            State.NONE: [ExitCode.MISSING],
            State.NOT_RELEVANT: [
                ExitCode.ENDPOINT_NOT_RELEVANT,
                ExitCode.INSUFFICIENT_PRIVILEGES,
                ExitCode.TEST_NOT_RELEVANT,
            ],
            State.PROTECTED: [
                ExitCode.BLOCKED,
                ExitCode.BLOCKED_AT_PERIMETER,
                ExitCode.DYNAMIC_QUARANTINE,
                ExitCode.EXPLOIT_PREVENTED,
                ExitCode.PREVENTED_EXECUTION,
                ExitCode.PROCESS_BLOCKED,
                ExitCode.PROCESS_BLOCKED_GRACEFULLY,
                ExitCode.PROTECTED,
                ExitCode.STATIC_QUARANTINE,
            ],
            State.UNPROTECTED: [
                ExitCode.UNPROTECTED,
            ],
        }


class DOS(Enum):
    none = "none"
    arm64 = "arm64"
    x86_64 = "x86_64"
    aarch64 = "arm64"
    amd64 = "x86_64"
    x86 = "x86_64"

    @classmethod
    def normalize(cls, dos: str):
        try:
            arch = dos.split("-", 1)[-1]
            return dos[: -len(arch)].lower() + cls[arch.lower()].value
        except (KeyError, IndexError, AttributeError):
            return cls.none.value


class Control(Enum, metaclass=MissingItem):
    INVALID = -1
    NONE = 0
    CROWDSTRIKE = 1
    DEFENDER = 2
    SPLUNK = 3
    SENTINELONE = 4
    VECTR = 5
    S3 = 6
    INTUNE = 7
    SERVICENOW = 8
    OKTA = 9
    M365 = 10
    ENTRA = 11
    JAMF = 12
    CROWDSTRIKE_IDENTITY = 13
    GMAIL = 14
    GOOGLE_IDENTITY = 15

    @classmethod
    def _missing_(cls, value):
        return Control.INVALID

    @property
    def control_category(self):
        for k, v in ControlCategory.mapping().items():
            if self in v:
                return k
        return ControlCategory.NONE

    @property
    def scm_category(self):
        for k, v in SCMCategory.control_mapping().items():
            if self in v:
                return k
        return SCMCategory.NONE


class ControlCategory(Enum, metaclass=MissingItem):
    INVALID = -1
    NONE = 0
    CLOUD = 1
    EMAIL = 2
    IDENTITY = 3
    NETWORK = 4
    XDR = 5
    ASSET_MANAGER = 6

    @classmethod
    def _missing_(cls, value):
        return ControlCategory.INVALID

    @classmethod
    def mapping(cls):
        return {
            ControlCategory.ASSET_MANAGER: [
                Control.INTUNE,
                Control.SERVICENOW,
                Control.JAMF,
            ],
            ControlCategory.CLOUD: [],
            ControlCategory.EMAIL: [
                Control.GMAIL,
                Control.M365,
            ],
            ControlCategory.IDENTITY: [
                Control.CROWDSTRIKE_IDENTITY,
                Control.ENTRA,
                Control.GOOGLE_IDENTITY,
                Control.OKTA,
            ],
            ControlCategory.NETWORK: [],
            ControlCategory.XDR: [
                Control.CROWDSTRIKE,
                Control.DEFENDER,
                Control.SENTINELONE,
            ],
        }


class SCMCategory(Enum, metaclass=MissingItem):
    INVALID = -1
    NONE = 0
    ENDPOINT = 1
    INBOX = 2
    USER = 3

    @classmethod
    def _missing_(cls, value):
        return SCMCategory.INVALID

    @classmethod
    def control_mapping(cls):
        return {
            SCMCategory.ENDPOINT: [
                Control.CROWDSTRIKE,
                Control.DEFENDER,
                Control.INTUNE,
                Control.JAMF,
                Control.SENTINELONE,
                Control.SERVICENOW,
            ],
            SCMCategory.USER: [
                Control.CROWDSTRIKE_IDENTITY,
                Control.ENTRA,
                Control.GOOGLE_IDENTITY,
                Control.OKTA,
            ],
            SCMCategory.INBOX: [
                Control.GMAIL,
                Control.M365,
            ],
        }

    @classmethod
    def category_mapping(cls):
        return {
            SCMCategory.ENDPOINT: [ControlCategory.ASSET_MANAGER, ControlCategory.XDR],
            SCMCategory.USER: [ControlCategory.IDENTITY],
            SCMCategory.INBOX: [ControlCategory.EMAIL],
        }


class BackgroundJobTypes(Enum, metaclass=MissingItem):
    INVALID = -1
    UPDATE_SCM = 1
    DEPLOY_PROBE = 2
    OBSERVED_DETECTED = 3
    PRELUDE_ENDPOINT_SYNC = 4
    EXPORT_SCM = 5

    @classmethod
    def _missing_(cls, value):
        return BackgroundJobTypes.INVALID


class EDRResponse(Enum, metaclass=MissingItem):
    INVALID = -1
    OBSERVE = 1
    DETECT = 2
    PREVENT = 3

    @classmethod
    def _missing_(cls, value):
        return EDRResponse.INVALID


class PartnerEvents(Enum, metaclass=MissingItem):
    INVALID = -1
    REDUCED_FUNCTIONALITY_MODE = 1
    NO_EDR = 2
    MISSING_EDR_POLICY = 3
    MISSING_AV_POLICY = 4
    MISSING_MFA = 5
    NO_ASSET_MANAGER = 6
    MISCONFIGURED_POLICY_SETTING = 7

    @classmethod
    def _missing_(cls, value):
        return PartnerEvents.INVALID

    @classmethod
    def control_category_mapping(cls):
        return {
            PartnerEvents.REDUCED_FUNCTIONALITY_MODE: [ControlCategory.XDR],
            PartnerEvents.NO_EDR: [
                ControlCategory.XDR,
            ],
            PartnerEvents.MISSING_EDR_POLICY: [ControlCategory.XDR],
            PartnerEvents.MISSING_AV_POLICY: [ControlCategory.XDR],
            PartnerEvents.MISSING_MFA: [ControlCategory.IDENTITY],
            PartnerEvents.NO_ASSET_MANAGER: [ControlCategory.ASSET_MANAGER],
            PartnerEvents.MISCONFIGURED_POLICY_SETTING: [
                ControlCategory.XDR,
                ControlCategory.EMAIL,
                ControlCategory.IDENTITY,
            ],
        }


class AlertTypes(Enum, metaclass=MissingItem):
    INVALID = -1
    NEW_REDUCED_FUNCTIONALITY_MODE_ENDPOINTS = 1
    NEW_NO_EDR_ENDPOINTS = 2
    NEW_MISSING_EDR_POLICY_ENDPOINTS = 3
    NEW_MISSING_AV_POLICY_ENDPOINTS = 4
    NEW_MISSING_MFA_USERS = 5
    NEW_NO_ASSET_MANAGER_ENDPOINTS = 6
    NEW_POLICY_SETTING_FAILURE = 7
    NEW_POLICY_SETTING_PASS = 8

    @classmethod
    def _missing_(cls, value):
        return AlertTypes.INVALID


class AuditEvent(Enum, metaclass=MissingItem):
    INVALID = 0
    ATTACH_PARTNER = 1
    CREATE_DETECTION = 25
    CREATE_TEST = 2
    CREATE_THREAT = 18
    CREATE_USER = 3
    DELETE_DETECTION = 26
    DELETE_ENDPOINT = 4
    DELETE_TEST = 5
    DELETE_THREAT = 20
    DELETE_USER = 6
    DETACH_PARTNER = 7
    DISABLE_TEST = 8
    DOWNLOAD_TEST_ATTACHMENT = 9
    ENABLE_TEST = 10
    PARTNER_BLOCK_TEST = 11
    REGISTER_ENDPOINT = 12
    SCHEDULE = 23
    UNSCHEDULE = 24
    UPDATE_ACCOUNT = 13
    UPDATE_DETECTIONS = 27
    UPDATE_ENDPOINT = 14
    UPDATE_TEST = 15
    UPDATE_THREAT = 19
    UPDATE_USER = 17
    UPLOAD_TEST_ATTACHMENT = 16
    # Next value: 28

    @classmethod
    def _missing_(cls, value):
        return AuditEvent.INVALID


class PolicyType(Enum, metaclass=MissingItem):
    INVALID = 0
    EDR = 1
    AV = 2
    IDENTITY_PASSWORD = 3
    EMAIL_ANTIPHISH = 4
    EMAIL_OUTBOUND = 5
    EMAIL_CONTENT = 6
    EMAIL_MALWARE = 7
    EMAIL_ATTACHMENT = 8
    EMAIL_LINKS = 9
    EMAIL_DKIM = 10
    DEVICE_COMPLIANCE = 11
    IDENTITY_MFA = 12

    @classmethod
    def _missing_(cls, value):
        return PolicyType.INVALID


class Platform(Enum, metaclass=MissingItem):
    INVALID = 0
    WINDOWS = 1
    DARWIN = 2
    LINUX = 3
    ALL = 4

    @classmethod
    def _missing_(cls, value):
        return Platform.INVALID
