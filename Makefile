REBAR=rebar3

.DEFAULT_GOAL: compile

compile:
	$(REBAR) compile
	
ct:
	$(REBAR) ct

test:
	$(REBAR) ct
