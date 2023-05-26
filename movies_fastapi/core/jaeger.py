from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter
)

from core.config import settings


def config_jaeger():
    trace.set_tracer_provider(TracerProvider(resource=Resource({'service.name': 'Movies API'})))
    if settings.tests:
        pass
    # elif not settings.debug:
    #     # opentelemetry for staging or production
    #     trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        # opentelemetry + jaeger for development
        # requires jaeger running in a container
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(JaegerExporter(
                agent_host_name=settings.JAEGER_HOST,
                agent_port=int(settings.JAEGER_PORT),)))


def init_jaeger(app):
    FastAPIInstrumentor.instrument_app(app)
    return app
