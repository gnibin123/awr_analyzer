"""awr_analyzer: parse Oracle AWR reports and generate plain-language,
actionable performance insights and trend forecasts."""

from .analyzer import analyze
from .forecast import build_trend
from .models import AnalysisResult, AWRReport, Finding
from .parser import parse_awr_file, parse_awr_html

__version__ = "0.1.0"

__all__ = [
    "analyze",
    "build_trend",
    "parse_awr_file",
    "parse_awr_html",
    "AWRReport",
    "AnalysisResult",
    "Finding",
    "__version__",
]
