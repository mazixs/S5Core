package diagnostics

import (
	"context"
	"runtime/trace"
	"strconv"
)

// operation marks a periodic call in the flight recorder's trace with its
// flow, so the trace of an incident shows where that call spent its time.
// The zero operation marks nothing.
type operation struct {
	task   *trace.Task
	region *trace.Region
}

func (r *recorder) beginOperation(f *flowInfo, name string) operation {
	if r.flight == nil || !trace.IsEnabled() {
		return operation{}
	}
	ctx, task := trace.NewTask(context.Background(), "s5core.operation")
	trace.Log(ctx, "s5core.flow", strconv.FormatUint(uint64(f.id), 10))
	return operation{task: task, region: trace.StartRegion(ctx, name)}
}

func (o operation) end() {
	if o.task != nil {
		o.region.End()
		o.task.End()
	}
}
