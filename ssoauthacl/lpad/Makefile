include $(GOROOT)/src/Make.inc

TARG=launchpad.net/lpad

GOFILES=\
	archive.go\
	blueprint.go\
	build.go\
	builder.go\
	branch.go\
	bug.go\
	oauth.go\
	person.go\
	project.go\
	distro.go\
	source.go\
	session.go\
	value.go\

include $(GOROOT)/src/Make.pkg

runexample: _obj/launchpad.net/lpad.a
	$(GC) -I _obj -o example.$(O) example.go
	$(LD) -L _obj -o example example.$(O)
	./example

GOFMT=gofmt
BADFMT=$(shell $(GOFMT) -l $(GOFILES) $(wildcard *_test.go))

gofmt: $(BADFMT)
	@for F in $(BADFMT); do $(GOFMT) -w $$F && echo $$F; done

ifneq ($(BADFMT),)
ifneq ($(MAKECMDGOALS),gofmt)
#$(warning WARNING: make gofmt: $(BADFMT))
endif
endif
