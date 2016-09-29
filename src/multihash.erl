-module(multihash).

-define(IDENTITY, 16#00).
-define(SHA1, 16#11).
-define(SHA2_256, 16#12).
-define(SHA2_512, 16#13).
-define(SHA3_512, 16#14).
-define(SHA3_384, 16#15).
-define(SHA3_256, 16#16).
-define(SHA3_224, 16#17).
-define(SHAKE_128, 16#18).
-define(SHAKE_256, 16#19).
-define(BLAKE2B, 16#40).
-define(BLAKE2S, 16#41).

-type hash_algorithm() :: 'identity'
                        | 'sha1'
                        | 'sha2-256' | 'sha2-512'
                        | 'sha3-512' | 'sha3-384' | 'sha3-256' | 'sha3-224'
                        | 'shake-128' | 'shake-256'
                        | 'blake2b' | 'blake2s'.

-type hash_function() :: fun((Bin :: binary()) -> binary()).
-type function_code() :: non_neg_integer().
-type digest_size() :: non_neg_integer().

-export_type([hash_algorithm/0]).

-export([hash/3, decode/1, supported/0]).

-spec hash(hash_algorithm(), digest_size(), binary()) -> iodata().
hash(Algo, Size, Bin) ->
    {Code, HashFun} = hash_info(Algo),
    <<Digest:Size/binary, _Rest/binary>> = HashFun(Bin),
    [varint:encode(Code), varint:encode(Size), Digest].

-spec decode(binary()) -> {hash_algorithm(), binary()}.
decode(Bin0) ->
    {Algo, Bin1} = varint:decode(Bin0),
    {Size, Bin2} = varint:decode(Bin1),
    <<Digest:Size/binary, Rest/binary>> = Bin2,
    {Digest, Rest}.

-spec supported() -> list(hash_algorithm()).
supported() ->
    ['identity', 'sha1', 'sha2-256', 'sha2-512'].

-spec hash_info(hash_algorithm()) -> {function_code(), digest_size() | infinity, hash_function()} | {error, unimplemented}.
hash_info('identity') ->
    {?IDENTITY, infinity, fun (Bin) -> Bin end};
hash_info('sha1') ->
    {?SHA1, 20, fun (Bin) -> crypto:hash(sha, Bin) end};
hash_info('sha2-256') ->
    {?SHA2_256, 32, fun (Bin) -> crypto:hash(sha256, Bin) end};
hash_info('sha2-512') ->
    {?SHA2_512, 64, fun (Bin) -> crypto:hash(sha512, Bin) end};
hash_info('sha3-512') ->
    {error, unimplemented};
hash_info('sha3-384') ->
    {error, unimplemented};
hash_info('sha3-256') ->
    {error, unimplemented};
hash_info('sha3-224') ->
    {error, unimplemented};
hash_info('shake-128') ->
    {error, unimplemented};
hash_info('shake-256') ->
    {error, unimplemented};
hash_info('blake2b') ->
    {error, unimplemented};
hash_info('blake2s') ->
    {error, unimplemented}.

decode_function_code(Bin0) ->
    case varint:decode(Bin0) of
        {ok, FunctionCode, Bin1} ->
            case function_code_to_atom(FunctionCode) of
                Algo when is_atom(Algo) ->
                    {ok, Algo, Bin1};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

function_code_to_atom(?IDENTITY)-> 'identity';
function_code_to_atom(?SHA1) -> 'sha1';
function_code_to_atom(?SHA2_256) -> 'sha2-256';
function_code_to_atom(?SHA2_512) -> 'sha2-512';
function_code_to_atom(?SHA3_512) -> 'sha3-512';
function_code_to_atom(?SHA3_384) -> 'sha3-384';
function_code_to_atom(?SHA3_256) -> 'sha3-256';
function_code_to_atom(?SHA3_224) -> 'sha3-224';
function_code_to_atom(?SHAKE_128) -> 'shake-128';
function_code_to_atom(?SHAKE_256) -> 'shake-256';
function_code_to_atom(?BLAKE2B) -> 'blake2b';
function_code_to_atom(?BLAKE2S) -> 'blake2s'.
