"""Cross-file taint source. The tainted value is sanitised nowhere before reaching services.py."""
from flask import Blueprint, request

from src.sast.crossfile import services

bp = Blueprint("ops", __name__)


@bp.route("/ops/restart")
def restart():
    return services.restart_service(request.args["service"])


@bp.route("/ops/report")
def report():
    return services.report_rows(request.args["table"])
