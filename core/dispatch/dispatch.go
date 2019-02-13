package dispatch

import "github.com/renproject/auther/core/resolver"

const JobQueueCapacity = 256
const NumWorkers = 256

type Job interface {
	IsJob()
}

type Dispatcher struct {
	r     resolver.Resolver
	queue <-chan Job
}

func New(r resolver.Resolver, queue <-chan Job) *Worker {
	return &Worker{r, queue}
}

func (d *Dispatcher) Run(done <-chan struct{}) {
	co.ParForAll(NumWorkers, func(i int) {
		NewWorker(d.r, d.queue).Run(done)
	})
}

type Worker struct {
	r     resolver.Resolver
	queue <-chan Job
}

func NewWorker(r resolver.Resolver, queue <-chan Job) *Worker {
	return &Worker{r, queue}
}

func (w *Worker) Run(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case job := <-w.queue:
			switch job := job.(type) {
			// TODO: Delegate the work to the resolver.
			}
		}
	}
}
