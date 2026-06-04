"""Command-line smoke interface for local MVP demos."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import DataGrade, GatewayRequest, ModelZone
from kai_security.reports.generator import generate_usage_summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kai-security")
    subcommands = parser.add_subparsers(dest="command", required=True)

    evaluate = subcommands.add_parser("evaluate", help="Evaluate a prompt through the gateway")
    evaluate.add_argument("--prompt", required=True)
    evaluate.add_argument("--user-id", default="local-user")
    evaluate.add_argument("--department", default="demo")
    evaluate.add_argument("--data-grade", choices=[grade.value for grade in DataGrade], default="internal")
    evaluate.add_argument("--model-zone", choices=[zone.value for zone in ModelZone], default="external")
    evaluate.add_argument("--requested-model", default="gpt-compatible")

    args = parser.parse_args(argv)
    if args.command == "evaluate":
        service = GatewayService()
        request = GatewayRequest(
            prompt=args.prompt,
            user_id=args.user_id,
            department=args.department,
            data_grade=DataGrade(args.data_grade),
            model_zone=ModelZone(args.model_zone),
            requested_model=args.requested_model,
        )
        evaluation = service.evaluate(request)
        decision = evaluation.decision
        route = choose_route(decision, request.requested_model)
        summary = generate_usage_summary(service.evidence_store.list_events())
        print(
            json.dumps(
                {
                    "request_id": request.request_id,
                    "decision": decision,
                    "effective_prompt": evaluation.effective_prompt,
                    "prompt_changed": evaluation.prompt_changed,
                    "approval_id": evaluation.approval_id,
                    "route": route,
                    "summary": summary,
                },
                ensure_ascii=False,
                indent=2,
                default=_json_default,
            )
        )
        return 0
    return 2


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(f"Unsupported JSON value: {type(value)!r}")


if __name__ == "__main__":
    raise SystemExit(main())
