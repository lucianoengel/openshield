# Build the OpenShield control plane (T-025).
#
# Multi-stage: compile the Go binary, then a minimal runtime image with no root.
# Only the control plane is containerised — the agent and worker need host access
# (fanotify) a container does not have, so they run on the endpoint.
FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
# Module cache: copy go.mod/go.sum first so deps layer-cache across code changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure Go, no CGO — a static binary that runs in a minimal image.
RUN CGO_ENABLED=0 go build -o /out/openshield-server ./cmd/openshield-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/openshield-server /usr/bin/openshield-server
# nonroot user (uid 65532) is provided by the base image.
USER nonroot
ENTRYPOINT ["/usr/bin/openshield-server"]
