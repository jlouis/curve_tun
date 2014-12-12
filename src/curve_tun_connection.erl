-module(curve_tun_connection).
-behaviour(gen_fsm).

-export([connect/3, accept/1, listen/2, send/2, close/1, recv/1]).

%% Private callbacks
-export([start_link/0]).

%% FSM callbacks
-export([init/1, code_change/4, terminate/3, handle_info/3, handle_event/3, handle_sync_event/4]).

-export([
	closed/2, closed/3,
	connected/2, connected/3,
	initiating/2, initiating/3,
	ready/2, ready/3
]).

-record(curve_tun_socket, { pid :: pid() }).
%% The state record is currently unused...
%% -record(state, {}). 

connect(Address, Port, Options) ->
    {ok, Pid} = start_link(),
    case gen_fsm:sync_send_event(Pid, {connect, Address, Port, Options}) of
        ok ->
            {ok, #curve_tun_socket { pid = Pid }};
        {error, Reason} ->
            {error, Reason}
    end.

send(#curve_tun_socket { pid = Pid }, Msg) ->
    gen_fsm:sync_send_event(Pid, {send, Msg}).

recv(#curve_tun_socket { pid = Pid }) ->
    gen_fsm:sync_send_event(Pid, recv).

close(#curve_tun_socket { pid = Pid }) ->
    gen_fsm:sync_send_event(Pid, close).

listen(Port, Opts) ->
    Options = [binary, {packet, 2}, {active, false} | Opts],
    gen_tcp:listen(Port, Options).

accept(LSock) ->
    {ok, Pid} = start_link(),
    case gen_fsm:sync_send_event(Pid, {accept, LSock}) of
       ok ->
           {ok, #curve_tun_socket { pid = Pid }};
       {error, Reason} ->
           {error, Reason}
   end.

%% @private
start_link() ->
    gen_fsm:start_link(?MODULE, [], []).
    
%% @private
init([]) ->
    State = #{
        vault => curve_tun_vault_dummy,
        registry => curve_tun_simple_registry
    },
    {ok, ready, State}.


%% @private
ready({accept, LSock}, From, # { vault := Vault } = State) ->
    case gen_tcp:accept(LSock) of
        {error, Reason} ->
            {stop, normal, {error, Reason}, ready, State};
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{active, once}]),
            {ok, EC} = recv_hello(Socket, Vault),
            case send_cookie(Socket, EC, Vault) of
                ok ->
                    inet:setopts(Socket, [{active, once}]),
                    {next_state, accepting, State#{ socket => Socket, from => From }};
                {error, Reason} ->
                    {stop, normal, {error, Reason}, State}
           end
    end;
ready({connect, Address, Port, Options}, From, State) ->
    TcpOpts = lists:keydelete(key, 1, [{packet, 2}, binary, {active, false} | Options]),
    ServerKey = proplists:get_value(key, Options),
    case gen_tcp:connect(Address, Port, TcpOpts) of
        {error, Reason} ->
            {stop, normal, {error, Reason}, State};
        {ok, Socket} ->
            #{ public := EC, secret := ECs } = enacl:box_keypair(),
            case send_hello(Socket, ServerKey, EC, ECs) of
                ok ->
                    inet:setopts(Socket, [{active, once}]),
                    {next_state, initiating, State#{
                    	from => From,
                    	socket => Socket,
                    	public_key => EC,
                    	secret_key => ECs,
                    	peer_lt_public_key => ServerKey }};
                {error, Reason} ->
                    {stop, normal, {error, Reason}, State}
            end
    end.
    
ready(_Msg, ready) ->
    {stop, argh, ready}.

initiating(_Msg, _From, _State) ->
    {stop, argh, ready}.

initiating(_Msg, _) ->
    {stop, argh, ready}.

closed(_Msg, _State) ->
    {stop, argh, closed}.
    
closed({send, _}, _From, State) ->
    {reply, {error, closed}, State}.

connected(_M, _) ->
    {stop, argh, connected}.

connected(close, _From, #{ socket := Sock } = State) ->
    ok = gen_tcp:close(Sock),
    {stop, normal, ok, connected, maps:remove(socket, State)};
connected(recv, From, #{ socket := Sock, recv_queue := Q } = State) ->
    ok = handle_socket(Sock, next),
    {noreply, connected, State#{ recv_queue := queue:in(From, Q) }};
connected({send, M}, _From, State) ->
    {Reply, NState} = send_msg(M, State),
    {reply, Reply, connected, NState}.

handle_sync_event(Event, _From, Statename, State) ->
    error_logger:info_msg("Unknown sync_event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_event(Event, Statename, State) ->
    error_logger:info_msg("Unknown event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_info({tcp, Sock, Data}, Statename, #{ socket := Sock } = State) ->
    case handle_packet(Data, Statename, State) of
        {Next, connected, NewState} ->
            NextState = NewState#{ recv_queue => queue:new(), buf => undefined },
            handle_socket(Sock, Next),
            {next_state, connected, reply(ok, NextState)};
        {Next, NewStateName, NewState} ->
            handle_socket(Sock, Next),
            {next_state, NewStateName, NewState};
        {error, _Reason} = Err ->
            {stop, Statename, reply(Err, State)}
    end;
handle_info({tcp_closed, S}, Statename, # { socket := S } = State) ->
    handle_tcp_closed(Statename, State);
handle_info(Info, Statename, State) ->
    error_logger:info_msg("Unknown info msg ~p in state ~p", [Info, Statename]),
    {next_state, Statename, State}.

terminate(_Reason, _Statename, _State) ->
    ok.

code_change(_OldVsn, Statename, State, _Aux) ->
    {ok, Statename, State}.

%% Internal handlers

handle_socket(Sock, next) -> inet:setopts(Sock, [{active, once}]);
handle_socket(_Sock, hold) -> ok.

handle_recv_queue(#{ recv_queue := Q, buf := Buf } = State) ->
    case {queue:out(Q), Buf} of
        {{{value, _Receiver}, _Q2}, undefined} ->
            {next, connected, State};
        {{{value, Receiver}, Q2}, Msg} ->
            gen_fsm:reply(Receiver, Msg),
            handle_recv_queue(State#{ recv_queue := Q2, buf := undefined });
        {{empty, _Q2}, _} ->
            {hold, connected, State}
   end.

handle_packet(<<109,27,57,203,246,90,17,180, N:64/integer, Box/binary>>, % MSG
	connected, #{ peer_public_key := P, secret_key := Ks, buf := undefined } = State) ->
    Nonce = st_nonce(msg, client, N),
    {ok, Msg} = enacl:box_open(Box, Nonce, P, Ks),
    handle_recv_queue(State#{ buf := Msg });
handle_packet(<<108,9,175,178,138,169,250,253, % VOUCH
                K:96/binary, N:64/integer, Box/binary>>,
	accepting, #{ socket := Sock, peer_public_key := EC, vault := Vault, registry := Registry } = State) ->
    case unpack_cookie(K) of
        {ok, EC, ESs} ->
            Nonce = st_nonce(vouch, client, N),
            {ok, <<C:32/binary, NonceLT:16/binary, Vouch/binary>>} = enacl:box_open(Box, Nonce, EC, ESs),
            true = Registry:verify(Sock, C),
            VNonce = lt_nonce(client, NonceLT),
            {ok, <<EC:32/binary>>} = Vault:box_open(Vouch, VNonce, C),
            %% Everything seems to be in order, go to connected state:
            {hold, connected, State# { secret_key := ESs }};
        {error, Reason} ->
            {error, Reason}
    end;
handle_packet(<<28,69,220,185,65,192,227,246, % COOKIE
                N:16/binary, Box/binary>>, initiating,
	#{ secret_key := ECs, peer_lt_public_key := S } = State) ->
    Nonce = lt_nonce(server, N),
    {ok, <<ES:32/binary, K/binary>>} = enacl:box_open(Box, Nonce, S, ECs),
    {ok, NState} = send_vouch(K, State#{ peer_public_key => ES }),
    {hold, connected, NState}.

handle_tcp_closed(_Statename, State) ->
    {next_state, closed, maps:remove(socket, State)}.

%% Internal functions

unpack_cookie(<<Nonce:16/binary, Cookie/binary>>) ->
    CNonce = lt_nonce(minute_k, Nonce),
    Keys = curve_tun_cookie:recent_keys(),
    unpack_cookie_(Keys, CNonce, Cookie).
    
unpack_cookie_([], _, _) -> {error, ecookie};
unpack_cookie_([K | Ks], CNonce, Cookie) ->
    case enacl:secretbox_open(Cookie, CNonce, K) of
        {ok, Msg} -> {ok, Msg};
        {error, verification_failed} ->
            unpack_cookie_(Ks, CNonce, Cookie)
    end.

reply(M, #{ from := From } = State) ->
    gen_fsm:reply(From, M),
    maps:remove(from, State).
    
%% Nonce generation

%% Short term nonces
st_nonce(hello, client, N) -> <<"CurveCP-client-H", N:64/integer>>;
st_nonce(initiate, client, N) -> <<"CurveCP-client-I", N:64/integer>>;
st_nonce(msg, client, N) -> <<"CurveCP-client-M", N:64/integer>>;
st_nonce(hello, server, N) -> <<"CurveCP-server-H", N:64/integer>>;
st_nonce(initiate, server, N) -> <<"CurveCP-server-I", N:64/integer>>;
st_nonce(msg, server, N) -> <<"CurveCP-server-M", N:64/integer>>.

lt_nonce(minute_k, N) -> <<"minute-k", N/binary>>;
lt_nonce(client, N) -> <<"CurveCPV", N/binary>>;
lt_nonce(server, N) -> <<"CurveCPK", N/binary>>.

send_hello(Socket, S, EC, ECs) ->
    N = 0,
    Nonce = st_nonce(hello, client, N),
    Box = enacl:box(binary:copy(<<0>>, 64), Nonce, S, ECs),
    H = <<108,9,175,178,138,169,250,252, EC:32/binary, N:64/integer, Box/binary>>,
    ok = gen_tcp:send(Socket, H).

send_cookie(Socket, EC, Vault) ->
    %% Once ES is in the hands of the client, the server doesn't need it anymore
    #{ public := ES, secret := ESs } = enacl:box_keypair(),

    Ts = curve_tun_cookie:current_key(),
    SafeNonce = Vault:safe_nonce(),
    CookieNonce = lt_nonce(minute_k, SafeNonce),

    %% Send the secret short term key roundtrip to the client under protection of a minute key
    KBox = enacl:secretbox(<<EC:32/binary, ESs:32/binary>>, CookieNonce, Ts),
    K = <<SafeNonce:16/binary, KBox/binary>>,
    Box = Vault:box(<<ES:32/binary, K/binary>>, SafeNonce, EC),
    Cookie = <<28,69,220,185,65,192,227,246, SafeNonce:16/binary, Box/binary>>,
    ok = gen_tcp:send(Socket, Cookie),
    ok.

recv_hello(Socket, Vault) ->
    receive
        {tcp, Socket, <<108,9,175,178,138,169,250,252, EC:32/binary, N:64/integer, Box/binary>>} ->
            recv_hello_(EC, st_nonce(hello, client, N), Box, Vault);
        {tcp, Socket, _Otherwise} ->
            {error, ehello}
   end.

recv_hello_(EC, Nonce, Box, Vault) ->
    {ok, <<0:512/integer>>} = Vault:box_open(Box, Nonce, EC),
    {ok, EC}.

vouch(Msg, S, Vault) ->
    Nonce = Vault:safe_nonce(),
    VNonce = lt_nonce(client, Nonce),
    Box = Vault:box(Msg, VNonce, S),
    {Box, Vault:public_key(), Nonce}.

send_vouch(Kookie, #{
	socket := Socket,
	public_key := EC,
	secret_key := ECs,
	peer_lt_public_key := S,
	peer_public_key := ES,
	vault := Vault } = State) ->
    {Vouch, C, NonceLT} = vouch(EC, S, Vault),
    N = 1,
    Nonce = st_nonce(initiate, client, N),
    Box = enacl:box(<<C:32/binary, NonceLT/binary, Vouch/binary>>, Nonce, ES, ECs),
    I = <<108,9,175,178,138,169,250,253, Kookie/binary, Nonce/binary, Box/binary>>,
    ok = gen_tcp:send(Socket, I),
    {ok, State#{ c => 2 }}.

send_msg(M, #{ socket := Socket, secret_key := Ks, peer_public_key := P, c := NonceCount } = State) ->
    Nonce = st_nonce(msg, client, NonceCount),
    Box = enacl:box(M, Nonce, P, Ks),
    M = <<109,27,57,203,246,90,17,180, NonceCount:64/integer, Box/binary>>,
    ok = gen_tcp:send(Socket, M),
    {ok, State#{ c := NonceCount + 1}}.
