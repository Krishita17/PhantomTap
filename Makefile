.PHONY: help install dev test demo benchmark figures audit samples monitor fleet attackpath case-study clean

PY ?= python3

help:
	@echo "PhantomTap — make targets"
	@echo "  install    editable install (core, no third-party deps)"
	@echo "  dev        editable install with test + figure extras"
	@echo "  test       run the pytest suite"
	@echo "  demo       end-to-end walkthrough on a synthetic deployment"
	@echo "  benchmark  attempts-to-characterize sweep -> docs/benchmark_results.*"
	@echo "  figures    regenerate all charts into docs/figures/"
	@echo "  audit      render a sample audit report to stdout"
	@echo "  monitor    blue-team detection demo on a badge-event stream"
	@echo "  fleet      multi-facility campus audit (weakest-link roll-up)"
	@echo "  attackpath path-of-least-resistance to a crown-jewel zone"
	@echo "  case-study full fleet audit -> examples/case_study_campus.{md,sarif}"
	@echo "  samples    regenerate synthetic datasets into data/synthetic/"
	@echo "  clean      remove caches and build artifacts"

install:
	$(PY) -m pip install -e .

dev:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

demo:
	$(PY) -m scripts.demo

benchmark:
	$(PY) -m scripts.run_benchmark

figures:
	$(PY) -m scripts.make_figures

audit:
	$(PY) -m phantomtap.cli audit --format H10301-26 --numbering sequential

monitor:
	$(PY) -m phantomtap.cli monitor --format H10301-26 --numbering sequential

fleet:
	$(PY) -m phantomtap.cli fleet --format H10306-34

attackpath:
	$(PY) -m phantomtap.cli attackpath --target datacenter

case-study:
	$(PY) -m scripts.case_study

samples:
	$(PY) -m scripts.make_samples

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
