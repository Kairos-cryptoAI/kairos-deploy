"""Isolated R7 profile of the reviewed exact, non-publishing inbox recovery.

R7 reuses the R5 recovery algorithm through private module instances. It never
patches R5 or the shared epoch worker globals, and it exposes only the three
R7-specific read/restore/exact-drain modes.
"""

from __future__ import annotations

import hashlib
import inspect
import types
from pathlib import Path
from types import MappingProxyType, ModuleType

if __package__:
    from scripts import runtime_epoch_read_recovery_worker as _r5_source
else:
    import runtime_epoch_read_recovery_worker as _r5_source

R7_OWNER = "69893dc7b7c647f49967387e7efca9fb"
R7_RESTORE_HOST = "kairos-epoch-69893dc7b7c6-restore-transport07"
R7_RESTORE_DATABASE = "kairos_recovery_69893dc7b7c6_epochrestore"
R7_EXPECTED_COUNTS = MappingProxyType(
    {"audit": 342_379, "outbox": 8_045, "inbox": 8_035}
)
R7_TARGETS = (
    MappingProxyType(
        {
            "outbox_id": 8049,
            "message_id": "c41e6d19c64f40205a685e48b0022946217c5869d5135d8bdba837918afeab89",
            "payload_sha256": "b9f4239abfaca5a483ed5a3d370ca79f02d221d02a8a3808d796a578b0a36696",
            "symbol": "XRPUSDT",
            "open_time_ms": 1_791_863_100_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8050,
            "message_id": "cd4ad6eb4dad60f7a28e9f48b4f3dd54acc07c2c8fe4431fb7242c2fb3b9600e",
            "payload_sha256": "a1442b10995616573f3ecb24d5bc63eb169bd6f6afbb3d9fea1557601fd7a3ce",
            "symbol": "XRPUSDT",
            "open_time_ms": 1_791_863_160_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8051,
            "message_id": "3c705f6255d184b6608b0dd35cc8d3f144b84ec888539ad7a70aa0a3b0daf136",
            "payload_sha256": "0831a4500473eb2d989a74d558da50343e003e61c1144271e7f2a675056a6268",
            "symbol": "ETHUSDT",
            "open_time_ms": 1_791_863_100_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8052,
            "message_id": "91af7a106ee4fa1cc9412427b6e9c400c93e3a60fe02b994ac73edee7fadaa59",
            "payload_sha256": "e875e183a904efe05a6f63525806c0fac5358cd2cdc0d6176b8b363bd9941ed9",
            "symbol": "ETHUSDT",
            "open_time_ms": 1_791_863_160_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8053,
            "message_id": "a80fad93c2168230a494e5b9229cae1efe198724114c02e905d58ece63bd7e10",
            "payload_sha256": "0301e5175ddc007e734e9d8d8481110a68abdb9bd72df65e7cedbc04c0cbc166",
            "symbol": "BNBUSDT",
            "open_time_ms": 1_791_863_100_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8054,
            "message_id": "f2c402415f8b409c48dc91540dcf1cf4b51275f5a086a69d4d52a721e1a31cf9",
            "payload_sha256": "a91b662f570ea7f7d9c30a4253adefd41efd6fc43fe71887ddf338599aaee2eb",
            "symbol": "BTCUSDT",
            "open_time_ms": 1_791_863_100_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8055,
            "message_id": "4bdce726769e11f1563feacf6e1904d0aae3f0072d80b62262fc0e043d4169f5",
            "payload_sha256": "cd052a7ecfee9c72d6e3a249aafe5fe3a4c0056bf61cf3573cc374421d10e012",
            "symbol": "SOLUSDT",
            "open_time_ms": 1_791_863_100_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8056,
            "message_id": "8fdccf94c0f1367b6c5cd88ddbfd6339a6315728ae9202046872fe5f1d5ef2ad",
            "payload_sha256": "399de6f047b892e02639a48f1205cc4ae0f73c3cdfec573c69d514ef2e8b1f80",
            "symbol": "BNBUSDT",
            "open_time_ms": 1_791_863_160_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8057,
            "message_id": "3745642e0eb2a69c590567a2bde5f855735d597e51fed988c25fc9406ed53ea9",
            "payload_sha256": "9fdde50c7bf07545487bc60265fd784489fd9404f558e9f081b05b4e2c7ac66e",
            "symbol": "SOLUSDT",
            "open_time_ms": 1_791_863_160_000,
        }
    ),
    MappingProxyType(
        {
            "outbox_id": 8058,
            "message_id": "2ca7f4ec33a3eed06bcda76af84570e99adfbcc71397207c500806ab7e9cfb2d",
            "payload_sha256": "d56d0bf532ea739225a2ff2553b73891777e3cccc9210f244ea8f06103a04fc9",
            "symbol": "BTCUSDT",
            "open_time_ms": 1_791_863_160_000,
        }
    ),
)
R7_TARGET_BY_ID = MappingProxyType({row["message_id"]: row for row in R7_TARGETS})
R7_TARGET_IDS = frozenset(R7_TARGET_BY_ID)
R7_TARGET_OUTBOX_IDS = frozenset(row["outbox_id"] for row in R7_TARGETS)
R7_MODES = frozenset({"r7-state", "r7-verify-restore", "r7-drain"})
R5_SOURCE_SHA256 = "21a1b9aec379126add77edb2f317f0e9becd1a580f94a9a78e5ecb3ae7095857"


def _clone_module_instance(
    source: ModuleType, module_name: str, overrides: dict[str, object]
) -> ModuleType:
    """Clone module functions/classes into a private globals dictionary."""
    target = ModuleType(module_name, source.__doc__)
    target.__dict__.update(vars(source))
    target.__dict__.update({"__name__": module_name, "__package__": source.__package__})
    target.__dict__.update(overrides)

    for name, value in tuple(vars(source).items()):
        if inspect.isfunction(value) and value.__module__ == source.__name__:
            target.__dict__[name] = _clone_function(value, target.__dict__, module_name)

    for name, value in tuple(vars(source).items()):
        if inspect.isclass(value) and value.__module__ == source.__name__:
            attributes = {
                key: _clone_class_attribute(item, target.__dict__, module_name)
                for key, item in vars(value).items()
                if key not in {"__dict__", "__weakref__", "__classcell__"}
            }
            attributes["__module__"] = module_name
            target.__dict__[name] = type(value.__name__, value.__bases__, attributes)
    return target


def _clone_function(function, globals_dict, module_name):
    clone = types.FunctionType(
        function.__code__,
        globals_dict,
        function.__name__,
        function.__defaults__,
        function.__closure__,
    )
    clone.__kwdefaults__ = function.__kwdefaults__
    clone.__annotations__ = dict(function.__annotations__)
    clone.__dict__.update(function.__dict__)
    clone.__doc__ = function.__doc__
    clone.__module__ = module_name
    clone.__qualname__ = function.__qualname__
    return clone


def _clone_class_attribute(value, globals_dict, module_name):
    if inspect.isfunction(value):
        return _clone_function(value, globals_dict, module_name)
    if isinstance(value, staticmethod):
        return staticmethod(_clone_function(value.__func__, globals_dict, module_name))
    if isinstance(value, classmethod):
        return classmethod(_clone_function(value.__func__, globals_dict, module_name))
    return value


def _verify_source_fingerprint() -> None:
    path = _r5_source.__file__
    if (
        not path
        or hashlib.sha256(Path(path).read_bytes()).hexdigest() != R5_SOURCE_SHA256
    ):
        raise _r5_source.epoch.EpochError("R7_REVIEWED_R5_HELPER_FINGERPRINT_MISMATCH")


_verify_source_fingerprint()
_R5_R7_INTERNAL = _clone_module_instance(
    _r5_source,
    "scripts._runtime_epoch_read_recovery_worker_r7_profile",
    {
        "OWNER": R7_OWNER,
        "EXPECTED_COUNTS": R7_EXPECTED_COUNTS,
        "CONSUMER_SERVICE": "kairos-epoch-consumer-" + R7_OWNER[:12],
        "RESTORE_HOST": R7_RESTORE_HOST,
        "RESTORE_DATABASE": R7_RESTORE_DATABASE,
        "TARGETS": R7_TARGETS,
        "TARGET_BY_ID": R7_TARGET_BY_ID,
        "TARGET_IDS": R7_TARGET_IDS,
        "TARGET_OUTBOX_IDS": R7_TARGET_OUTBOX_IDS,
        "PREFIX_EXCLUDED": ",".join(
            f"${index}" for index in range(1, len(R7_TARGETS) + 1)
        ),
    },
)


def _normalize_state(value: dict) -> dict:
    if not isinstance(value, dict):
        raise _r5_source.epoch.EpochError("EXACT_R7_FULL_STATE_REQUIRED")
    expected_owner = R7_OWNER
    if (
        value.get("owner") != expected_owner
        or value.get("mode") != "r7-state"
        or value.get("new_epoch_database") != "kairos_epoch_" + expected_owner[:12]
        or value.get("state") != "PASS_R7_STATE"
    ):
        raise _r5_source.epoch.EpochError("EXACT_R7_SIGNED_STATE_BINDING_REQUIRED")
    normalized = dict(value)
    normalized["mode"] = "r5-state"
    normalized["state"] = "PASS_R5_STATE"
    return normalized


def validate_expected_state(value: dict) -> dict:
    """Validate full R7 SQL/Redis evidence, returning private R5 shape."""
    normalized = _normalize_state(value)
    return _R5_R7_INTERNAL.validate_expected_state(normalized, include_redis=True)


def _normalize_config(mode: str, config: dict) -> tuple[str, dict]:
    if mode not in R7_MODES or not isinstance(config, dict):
        raise _r5_source.epoch.EpochError("EXACT_R7_PRIVATE_CONFIG_REQUIRED")
    internal_mode = mode.replace("r7-", "r5-", 1)
    normalized = dict(config)
    if mode == "r7-drain":
        normalized["expected_state"] = _normalize_state(config.get("expected_state"))
    elif mode == "r7-verify-restore":
        normalized["expected_seed"] = _normalize_state(config.get("expected_seed"))
    return internal_mode, normalized


def validate_config(mode: str, config: dict) -> None:
    internal_mode, normalized = _normalize_config(mode, config)
    _R5_R7_INTERNAL.validate_config(internal_mode, normalized)


def _translate_result(mode: str, result: dict) -> dict:
    states = {
        "PASS_R5_STATE": "PASS_R7_STATE",
        "PASS_R5_ISOLATED_RESTORE": "PASS_R7_ISOLATED_RESTORE",
        "PASS_EXACT_R5_INBOX_RECOVERY": "PASS_EXACT_R7_INBOX_RECOVERY",
    }
    translated = dict(result)
    state = translated.get("state")
    if state not in states:
        raise _r5_source.epoch.EpochError("R7_UNEXPECTED_INTERNAL_RESULT_STATE")
    translated["state"] = states[state]
    return translated


async def dispatch_r7(mode: str, config: dict, output: Path) -> dict:
    """Run only R7 state, isolated-restore verification, or exact inbox drain."""
    internal_mode, normalized = _normalize_config(mode, config)
    _R5_R7_INTERNAL.validate_config(internal_mode, normalized)
    result = await _R5_R7_INTERNAL.dispatch_r5(internal_mode, normalized, output)
    return _translate_result(mode, result)
