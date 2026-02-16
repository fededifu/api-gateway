package telemetry

import (
	"strconv"

	"go.opentelemetry.io/otel/attribute"
)

func methodAttr(method string) attribute.KeyValue {
	return attribute.String("method", method)
}

func pathAttr(path string) attribute.KeyValue {
	return attribute.String("path", path)
}

func statusAttr(status int) attribute.KeyValue {
	return attribute.String("status", strconv.Itoa(status))
}

func resultAttr(result string) attribute.KeyValue {
	return attribute.String("result", result)
}

func layerAttr(layer string) attribute.KeyValue {
	return attribute.String("layer", layer)
}

func backendAttr(backend string) attribute.KeyValue {
	return attribute.String("backend", backend)
}
