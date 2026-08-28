FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ARG SOURCE_DATE_EPOCH=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/sentinel/src \
    AI_SYSTEM_ROOT=/tmp/sentinel-ecommerce \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /opt/sentinel

RUN python -m pip install --no-cache-dir \
    pydantic==2.12.5 \
    PyYAML==6.0.3 \
    python-dotenv==1.2.1

RUN mkdir -p \
    /opt/sentinel/src/redsentinel/adapters/engine \
    /opt/sentinel/src/redsentinel/defenses/engine/security/firewall \
    /opt/sentinel/src/redsentinel/defenses/engine/security/output \
    && touch \
    /opt/sentinel/src/redsentinel/__init__.py \
    /opt/sentinel/src/redsentinel/adapters/__init__.py \
    /opt/sentinel/src/redsentinel/adapters/engine/__init__.py \
    /opt/sentinel/src/redsentinel/defenses/__init__.py \
    /opt/sentinel/src/redsentinel/defenses/engine/__init__.py \
    /opt/sentinel/src/redsentinel/defenses/engine/security/__init__.py \
    /opt/sentinel/src/redsentinel/defenses/engine/security/firewall/__init__.py \
    /opt/sentinel/src/redsentinel/defenses/engine/security/output/__init__.py

COPY src/redsentinel/adapters/engine/ecommerce_agent/ /opt/sentinel/src/redsentinel/adapters/engine/ecommerce_agent/
COPY src/redsentinel/defenses/engine/config.py /opt/sentinel/src/redsentinel/defenses/engine/config.py
COPY src/redsentinel/defenses/engine/security/audit.py /opt/sentinel/src/redsentinel/defenses/engine/security/audit.py
COPY src/redsentinel/defenses/engine/security/goal_guard.py /opt/sentinel/src/redsentinel/defenses/engine/security/goal_guard.py
COPY src/redsentinel/defenses/engine/security/tool_guard.py /opt/sentinel/src/redsentinel/defenses/engine/security/tool_guard.py
COPY src/redsentinel/defenses/engine/security/firewall/input_guard.py /opt/sentinel/src/redsentinel/defenses/engine/security/firewall/input_guard.py
COPY src/redsentinel/defenses/engine/security/output/filter.py /opt/sentinel/src/redsentinel/defenses/engine/security/output/filter.py

USER 65532:65532

ENTRYPOINT ["python", "-m", "redsentinel.adapters.engine.ecommerce_agent.runtime"]
CMD ["--message", "搜索耳机"]
