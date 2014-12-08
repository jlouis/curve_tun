-module(curve_tun_connection).
-behaviour(gen_fsm).

-export([connect/3, accept/1, listen/2]).

%% Private callbacks
-export([start_link/0]).

%% FSM callbacks
-export([init/1, code_change/4, terminate/3, handle_info/3, handle_event/3, handle_sync_event/4]).

-export([
	ready/2, ready/3,
	initiating/2, initiating/3
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

listen(Port, Opts) ->
    Options = [{packet, 2} | Opts],
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
                  {noreply, accepting, State#{ socket => Socket, from => From }};
                {error, Reason} ->
                   {stop, normal, {error, Reason}, ready, State}
           end
    end;
ready({connect, Address, Port, Options}, From, State) ->
    TcpOpts = [{packet, 2} | Options],
    ServerKey = proplists:get_value(key, Options),
    case gen_tcp:connect(Address, Port, TcpOpts) of
        {error, Reason} ->
            {stop, normal, {error, Reason}, ready, State};
        {ok, Socket} ->
            #{ public := EC, secret := ECs } = enacl:box_keypair(),
            case send_hello(Socket, ServerKey, EC, ECs) of
                ok ->
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, initiating, State#{
                    	from => From,
                    	socket => Socket,
                    	public_key => EC,
                    	secret_key => ECs,
                    	peer_lt_public_key => ServerKey }};
                {error, Reason} ->
                    {stop, normal, {error, Reason}, ready, State}
            end
    end.
    
ready(_Msg, ready) ->
    {stop, argh, ready}.

initiating(_Msg, _From, _State) ->
    {stop, argh, ready}.

initiating(_Msg, _) ->
    {stop, argh, ready}.

handle_sync_event(Event, _From, Statename, State) ->
    error_logger:info_msg("Unknown sync_event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_event(Event, Statename, State) ->
    error_logger:info_msg("Unknown event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_info({tcp, Sock, Data}, Statename, #{ socket := Sock } = State) ->
    ok = inet:setopts(Sock, [{active, once}]),
    case handle_packet(Data, Statename, State) of
        {ok, connected, NewState} -> {next_state, connected, wakeup(NewState)};
        {ok, NewStateName, NewState} -> {next_state, NewStateName, NewState}
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

handle_packet(<<108,9,175,178,138,169,250,253, % HELLO
                K:96/binary, N:64/integer-little, Box/binary>>,
	accepting, #{ socket := Sock, peer_public_key := EC, vault := Vault, registry := Registry } = State) ->
    case unpack_cookie(K) of
        {ok, EC, ESs} ->
            Nonce = st_nonce(vouch, client, N),
            {ok, <<C:32/binary, NonceLT:16/binary, Vouch/binary>>} = enacl:box_open(Box, Nonce, EC, ESs),
            true = Registry:verify(Sock, C),
            VNonce = lt_nonce(client, NonceLT),
            {ok, <<EC:32/binary>>} = Vault:box_open(Vouch, VNonce, C),
            %% Everything seems to be in order, go to connected state:
            {ok, connected, State# { secret_key := ESs }};
        {error, Reason} ->
            {error, Reason}
    end;
handle_packet(<<28,69,220,185,65,192,227,246, % COOKIE
                N:16/binary, Box/binary>>, initiating,
	#{ secret_key := ECs, peer_lt_public_key := S } = State) ->
    Nonce = lt_nonce(server, N),
    {ok, <<ES:32/binary, K/binary>>} = enacl:box_open(Box, Nonce, S, ECs),
    send_vouch(K, State#{ peer_public_key => ES }).

handle_tcp_closed(_Statename, _State) ->
	todo.

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

wakeup(#{ from := From } = State) ->
    gen_fsm:reply(From, ok),
    maps:remove(from, State).
    
%% Nonce generation

%% Short term nonces
st_nonce(hello, client, N) -> <<"CurveCP-client-H", N:64/integer-little>>;
st_nonce(initiate, client, N) -> <<"CurveCP-client-I", N:64/integer-little>>;
st_nonce(msg, client, N) -> <<"CurveCP-client-M", N:64/integer-little>>;
st_nonce(hello, server, N) -> <<"CurveCP-server-H", N:64/integer-little>>;
st_nonce(initiate, server, N) -> <<"CurveCP-server-I", N:64/integer-little>>;
st_nonce(msg, server, N) -> <<"CurveCP-server-M", N:64/integer-little>>.

lt_nonce(minute_k, N) -> <<"minute-k", N/binary>>;
lt_nonce(client, N) -> <<"CurveCPV", N/binary>>;
lt_nonce(server, N) -> <<"CurveCPK", N/binary>>.

send_hello(Socket, S, EC, ECs) ->
    N = 0,
    Nonce = st_nonce(hello, client, N),
    Box = enacl:box(binary:copy(<<0>>, 64), Nonce, S, ECs),
    H = <<108,9,175,178,138,169,250,252, EC:32/binary, N:64/integer-little, Box/binary>>,
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
        {tcp, Socket, <<108,9,175,178,138,169,250,252, EC:32/binary, N:64/integer-little, Box/binary>>} ->
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
    {ok, connected, State#{ c => 2 }}.

