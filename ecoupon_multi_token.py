
import smartpy as sp


class ErrorMessage:
    def token_undefined(): return "TOKEN_UNDEFINED"
    def insufficient_balance(): return "INSUFFICIENT_BALANCE"
    def not_operator(): return "NOT_OPERATOR"
    def not_owner(): return "NOT_OWNER"
    def transfer_of_zero(): return "TRANSFER_OF_ZERO"
    def invalid_signature(): return "INVALID_SIGNATURE"


class BatchTransfer:
    def get_transfer_type():
        tx_type = sp.TRecord(to_=sp.TAddress,
                             token_id=sp.TNat,
                             amount=sp.TNat).layout(
            ("to_", ("token_id", "amount"))
        )
        return sp.TRecord(from_=sp.TAddress,
                          txs=sp.TList(tx_type)).layout(
            ("from_", "txs"))

    def get_type():
        return sp.TList(BatchTransfer.get_transfer_type())

    def item(from_, txs):
        batch_transfer = sp.record(from_=from_, txs=txs)
        return sp.set_type_expr(batch_transfer, BatchTransfer.get_transfer_type())


class BatchMetaTransfer:
    def get_transfer_type():
        tx_type = sp.TRecord(to_=sp.TAddress,
                             token_id=sp.TNat,
                             amount=sp.TNat).layout(("to_", ("token_id", "amount")))

        return sp.TRecord(from_public_key=sp.TKey,
                          nonce=sp.TNat,
                          signature=sp.TSignature,
                          txs=sp.TList(tx_type)).layout(("from_public_key", ("signature", ("nonce", "txs"))))

    def get_type():
        return sp.TList(BatchMetaTransfer.get_transfer_type())

    def item(from_public_key, txs):
        batch_meta_transfer = sp.record(
            from_public_key=from_public_key, txs=txs)
        return sp.set_type_expr(batch_meta_transfer, BatchMetaTransfer.get_transfer_type())

    def get_signing_payload(batch_meta_transfer):
        tx_type = sp.TRecord(to_=sp.TAddress,
                             token_id=sp.TNat,
                             amount=sp.TNat).layout(("to_", ("token_id", "amount")))
        transfer_type = sp.TRecord(from_public_key=sp.TKey,
                                   nonce=sp.TNat,
                                   txs=sp.TList(tx_type)).layout(("from_public_key", ("nonce", "txs")))
        signing_payload = sp.record(from_public_key=batch_meta_transfer.from_public_key,
                                    nonce=batch_meta_transfer.nonce, txs=batch_meta_transfer.txs)

        return sp.set_type_expr(signing_payload, transfer_type)


class BatchMint:
    def get_mint_type():
        return sp.TRecord(address=sp.TAddress,
                          token_id=sp.TNat,
                          amount=sp.TNat).layout(("address", ("token_id", "amount"))
                                                 )

    def get_type():
        return sp.TList(BatchMint.get_mint_type())


class LedgerKey:
    def make(user, token):
        user = sp.set_type_expr(user, sp.TAddress)
        token = sp.set_type_expr(token, sp.TNat)
        result = sp.pair(user, token)
        return result


class BalanceOf:
    def request_type():
        return sp.TRecord(
            owner=sp.TAddress,
            token_id=sp.TNat).layout(("owner", "token_id"))

    def response_type():
        return sp.TList(
            sp.TRecord(
                request=BalanceOf.request_type(),
                balance=sp.TNat).layout(("request", "balance"))
        )

    def entry_point_type():
        return sp.TRecord(
            callback=sp.TContract(BalanceOf.response_type()),
            requests=sp.TList(BalanceOf.request_type())
        ).layout(("requests", "callback"))


class NonceOf:
    def request_type():
        return sp.TAddress

    def response_type():
        return sp.TList(
            sp.TRecord(
                owner=sp.TAddress,
                nonce=sp.TNat).layout(("owner", "nonce"))
        )


class TokenMetadata:
    def get_type():
        return sp.TRecord(
            token_id=sp.TNat,
            symbol=sp.TString,
            name=sp.TString,
            decimals=sp.TNat,
            extras=sp.TMap(sp.TString, sp.TString)
        ).layout(("token_id",
                  ("symbol",
                   ("name",
                    ("decimals", "extras")))))

    def set_type_and_layout(expr):
        sp.set_type(expr, TokenMetadata.get_type())

    def request_type():
        return TotalSupply.request_type()


class ECouponMultiToken(sp.Contract):
    def __init__(self, administrator):
        self.init(
            ledger=sp.big_map(tvalue=sp.TNat),
            nonces=sp.big_map(tvalue=sp.TNat),
            token_metadata=sp.big_map(tvalue=TokenMetadata.get_type()),
            administrator=administrator,
            proposed_administrator=administrator
        )

    @sp.entry_point
    def mutez_transfer(self, params):
        sp.verify(sp.sender == self.data.administrator)
        sp.set_type(params.destination, sp.TAddress)
        sp.set_type(params.amount, sp.TMutez)
        sp.send(params.destination, params.amount)

    @sp.entry_point
    def propose_administrator(self, params):
        sp.verify(sp.sender == self.data.administrator)
        sp.set_type(params, sp.TAddress)
        self.data.proposed_administrator = params

    @sp.entry_point
    def set_administrator(self, params):
        sp.verify(sp.sender == self.data.proposed_administrator)
        sp.verify(self.data.proposed_administrator == params)
        sp.set_type(params, sp.TAddress)
        self.data.administrator = params

    @sp.entry_point
    def mint(self, params):
        sp.verify(sp.sender == self.data.administrator)
        user = LedgerKey.make(params.address, params.token_id)

        self.data.ledger[user] = self.data.ledger.get(user, 0) + params.amount

        sp.if ~self.data.token_metadata.contains(params.token_id):
            token_metadata = sp.record(
                token_id=params.token_id,
                symbol=params.symbol,
                name=params.name,
                decimals=params.decimals,
                extras=sp.map()
            )
            TokenMetadata.set_type_and_layout(token_metadata)
            self.data.token_metadata[params.token_id] = token_metadata

    @sp.entry_point
    def meta_transfer(self, params):
        sp.verify(sp.sender == self.data.administrator)
        sp.set_type(params, BatchMetaTransfer.get_type())

        sp.for meta_transfer in params:
            source_account_key_hash = sp.hash_key(
                meta_transfer.from_public_key)
            source_account = sp.to_address(
                sp.implicit_account(source_account_key_hash))

            sp.verify(self.data.nonces.get(
                source_account, 0)+1 == meta_transfer.nonce)

            packed_data = sp.pack(
                BatchMetaTransfer.get_signing_payload(meta_transfer))

            sp.verify(sp.check_signature(meta_transfer.from_public_key,
                                         meta_transfer.signature, packed_data), message=ErrorMessage.invalid_signature())

            self.data.nonces[source_account] = meta_transfer.nonce

            sp.for tx in meta_transfer.txs:
                from_user = LedgerKey.make(source_account, tx.token_id)
                to_user = LedgerKey.make(tx.to_, tx.token_id)
                sp.verify(tx.amount > 0,
                          message=ErrorMessage.transfer_of_zero())
                sp.verify(self.data.ledger[from_user] >= tx.amount,
                          message=ErrorMessage.insufficient_balance())
                self.data.ledger[from_user] = sp.as_nat(
                    self.data.ledger[from_user] - tx.amount)
                self.data.ledger[to_user] = self.data.ledger.get(
                    to_user, 0) + tx.amount

                sp.if self.data.ledger[from_user] == 0:
                    del self.data.ledger[from_user]

    @sp.entry_point
    def transfer(self, params):
        # only admin can transfer
        sp.verify(sp.sender == self.data.administrator)
        sp.set_type(params, BatchTransfer.get_type())
        sp.for transfer in params:
            # admin can impersonate everyone so we don't check.
            sp.for tx in transfer.txs:
                from_user = LedgerKey.make(transfer.from_, tx.token_id)
                to_user = LedgerKey.make(tx.to_, tx.token_id)

                sp.verify(self.data.ledger[from_user] >= tx.amount,
                          message=ErrorMessage.insufficient_balance())

                self.data.ledger[from_user] = sp.as_nat(
                    self.data.ledger[from_user] - tx.amount)
                self.data.ledger[to_user] = self.data.ledger.get(
                    to_user, 0) + tx.amount

                sp.if self.data.ledger[from_user] == 0:
                    del self.data.ledger[from_user]

    @sp.entry_point
    def cleanup_nonce(self, params):
        # only admin can cleanup nonces
        sp.verify(sp.sender == self.data.administrator)
        sp.set_type(params, sp.TList(sp.TAddress))

        sp.for address in params:
            del self.data.nonces[address]

    @sp.entry_point
    def balance_of(self, params):
        sp.set_type(params, BalanceOf.entry_point_type())
        res = sp.local("responses", [])
        sp.set_type(res.value, BalanceOf.response_type())
        sp.for req in params.requests:
            user = LedgerKey.make(req.owner, req.token_id)
            balance = self.data.ledger[user]
            res.value.push(
                sp.record(
                    request=sp.record(
                        owner=sp.set_type_expr(req.owner, sp.TAddress),
                        token_id=sp.set_type_expr(req.token_id, sp.TNat)),
                    balance=balance))
        destination = sp.set_type_expr(params.callback,
                                       sp.TContract(BalanceOf.response_type()))
        sp.transfer(res.value.rev(), sp.mutez(0), destination)

    @sp.entry_point
    def nonce_of(self, params):
        res = sp.local("responses", [])
        sp.set_type(res.value, NonceOf.response_type())
        sp.for request in params.requests:
            nonce = self.data.nonces[request]
            res.value.push(sp.record(owner=request, nonce=nonce))
        destination = sp.set_type_expr(params.callback,
                                       sp.TContract(NonceOf.response_type()))
        sp.transfer(res.value.rev(), sp.mutez(0), destination)


class ViewConsumer(sp.Contract):
    def __init__(self):
        self.init(last_sum=0,
                  last_acc="",
                  last_nonces=sp.list(t=sp.TRecord(
                      owner=sp.TAddress,
                      nonce=sp.TNat)))

    @sp.entry_point
    def receive_balances(self, params):
        sp.set_type(params, BalanceOf.response_type())
        self.data.last_sum = 0
        sp.for resp in params:
            self.data.last_sum += resp.balance

    @sp.entry_point
    def receive_nonce(self, params):
        self.data.last_acc = ""
        self.data.last_nonces = params


def arguments_for_balance_of(receiver, reqs):
    return (sp.record(
        callback=sp.contract(Balance_of.response_type(),
                             sp.contract_address(receiver),
                             entry_point="receive_balances").open_some(),
        requests=reqs))


@sp.add_test(name="ECouponMultiToken Test")
def test():
    scenario = sp.test_scenario()
    scenario.h1("eCoupon - Multi-asset contracts")
    scenario.table_of_contents()
    # sp.test_account generates ED25519 key-pairs deterministically:
    admin = sp.test_account("Administrator")
    alice = sp.test_account("Alice")
    bob = sp.test_account("Robert")
    dan = sp.test_account("Dan")
    # Let's display the accounts:
    scenario.h2("Accounts")
    scenario.show([admin, alice, bob])
    c1 = ECouponMultiToken(admin.address)
    scenario += c1
    scenario.h2("Initial Minting")
    scenario.p("The administrator mints 100 token-0's to Alice.")
    scenario += c1.mint(address=alice.address,
                        amount=100,
                        symbol='TK0',
                        token_id=0, decimals=0, name="WETZ").run(sender=admin)

    scenario.h2("Meta Transacting")
    transaction1 = sp.record(
        to_=bob.address,
        token_id=0,
        amount=10)
    transaction2 = sp.record(
        to_=dan.address,
        token_id=0,
        amount=5)
    unsigned_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=1,
        txs=[transaction1, transaction2]
    )
    payload = sp.pack(
        BatchMetaTransfer.get_signing_payload(unsigned_meta_transfer))
    signature = sp.make_signature(alice.secret_key, payload)

    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=1,
        signature=signature,
        txs=[transaction1, transaction2]
    )

    # scenario.show(sp.unpack(sp.pack(sp.hash_key(alice.public_key))),html=False)
    scenario.p("perform first metatransfer (with nonce 1)")
    scenario += c1.meta_transfer([signed_meta_transfer]).run(sender=admin)

    scenario.p("replay attack: same message with nonce 1")
    scenario += c1.meta_transfer([signed_meta_transfer]
                                 ).run(sender=admin, valid=False)

    transaction2 = sp.record(
        to_=dan.address,
        token_id=0,
        amount=6)
    unsigned_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=1,
        txs=[transaction1, transaction2]
    )
    payload = sp.pack(
        BatchMetaTransfer.get_signing_payload(unsigned_meta_transfer))
    signature = sp.make_signature(alice.secret_key, payload)

    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=1,
        signature=signature,
        txs=[transaction1, transaction2]
    )
    scenario.p("replay attack: different message with nonce 1")
    scenario += c1.meta_transfer([signed_meta_transfer]
                                 ).run(sender=admin, valid=False)

    unsigned_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=2,
        txs=[transaction1, transaction2]
    )
    payload = sp.pack(
        BatchMetaTransfer.get_signing_payload(unsigned_meta_transfer))
    signature = sp.make_signature(alice.secret_key, payload)

    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=2,
        signature=signature,
        txs=[transaction1, transaction2]
    )
    scenario.p("next nonce transfer")
    scenario += c1.meta_transfer([signed_meta_transfer]).run(sender=admin)

    scenario.p("replay attack: lie about nonce (signed 2, saying 3)")
    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=3,
        signature=signature,
        txs=[transaction1, transaction2]
    )
    scenario += c1.meta_transfer([signed_meta_transfer]
                                 ).run(sender=admin, valid=False)

    scenario.p("replay attack: lie about nonce (signed 2, saying 1)")
    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=1,
        signature=signature,
        txs=[transaction1, transaction2]
    )
    scenario += c1.meta_transfer([signed_meta_transfer]
                                 ).run(sender=admin, valid=False)
    scenario.p("multi user meta transaction batching")
    unsigned_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=3,
        txs=[transaction1, transaction2]
    )
    payload = sp.pack(
        BatchMetaTransfer.get_signing_payload(unsigned_meta_transfer))
    signature = sp.make_signature(alice.secret_key, payload)

    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=3,
        signature=signature,
        txs=[transaction1, transaction2]
    )

    bob_transaction1 = sp.record(
        to_=alice.address,
        token_id=0,
        amount=1)
    bob_transaction2 = sp.record(
        to_=dan.address,
        token_id=0,
        amount=1)
    bob_unsigned_meta_transfer = sp.record(
        from_public_key=bob.public_key,
        nonce=1,
        txs=[bob_transaction1, bob_transaction2]
    )
    payload = sp.pack(BatchMetaTransfer.get_signing_payload(
        bob_unsigned_meta_transfer))
    signature = sp.make_signature(bob.secret_key, payload)

    bob_signed_meta_transfer = sp.record(
        from_public_key=bob.public_key,
        nonce=1,
        signature=signature,
        txs=[bob_transaction1, bob_transaction2]
    )

    dan_transaction1 = sp.record(
        to_=bob.address,
        token_id=0,
        amount=1)
    dan_transaction2 = sp.record(
        to_=alice.address,
        token_id=0,
        amount=1)
    dan_unsigned_meta_transfer = sp.record(
        from_public_key=dan.public_key,
        nonce=1,
        txs=[dan_transaction1, dan_transaction2]
    )
    payload = sp.pack(BatchMetaTransfer.get_signing_payload(
        dan_unsigned_meta_transfer))
    signature = sp.make_signature(dan.secret_key, payload)

    dan_signed_meta_transfer = sp.record(
        from_public_key=dan.public_key,
        nonce=1,
        signature=signature,
        txs=[dan_transaction1, dan_transaction2]
    )
    scenario += c1.meta_transfer([signed_meta_transfer, bob_signed_meta_transfer,
                                  dan_signed_meta_transfer]).run(sender=admin)

    scenario.p("normal user cannot publish meta transaction")
    unsigned_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=4,
        txs=[transaction1, transaction2]
    )
    payload = sp.pack(
        BatchMetaTransfer.get_signing_payload(unsigned_meta_transfer))
    signature = sp.make_signature(alice.secret_key, payload)

    signed_meta_transfer = sp.record(
        from_public_key=alice.public_key,
        nonce=4,
        signature=signature,
        txs=[transaction1, transaction2]
    )
    scenario += c1.meta_transfer([signed_meta_transfer]
                                 ).run(sender=alice, valid=False)
    scenario.h2("Normal Transfer (FA2)")
    scenario.p("normal user cannot transfer own funds")
    scenario += c1.transfer([BatchTransfer.item(from_=alice.address,
                                                txs=[
                                                    sp.record(to_=bob.address,
                                                              amount=1,
                                                              token_id=0)]),
                             BatchTransfer.item(from_=alice.address,
                                                txs=[
                                                    sp.record(to_=dan.address,
                                                              amount=1,
                                                              token_id=0)])
                             ]).run(sender=alice, valid=False)

    scenario.p("normal user cannot transfer other's funds")
    scenario += c1.transfer([BatchTransfer.item(from_=bob.address,
                                                txs=[
                                                    sp.record(to_=alice.address,
                                                              amount=1,
                                                              token_id=0)]),
                             BatchTransfer.item(from_=alice.address,
                                                txs=[
                                                    sp.record(to_=dan.address,
                                                              amount=1,
                                                              token_id=0)])
                             ]).run(sender=alice, valid=False)

    scenario.p("admin can transfer everything")
    scenario += c1.transfer([BatchTransfer.item(from_=bob.address,
                                                txs=[
                                                    sp.record(to_=alice.address,
                                                              amount=1,
                                                              token_id=0)]),
                             BatchTransfer.item(from_=alice.address,
                                                txs=[
                                                    sp.record(to_=dan.address,
                                                              amount=1,
                                                              token_id=0)])
                             ]).run(sender=admin)

    scenario.p("only admin can cleanup nonce")
    scenario += c1.cleanup_nonce([alice.address, bob.address,
                                  admin.address]).run(sender=bob, valid=False)

    scenario.p("correct admin can cleanup nonce")
    scenario += c1.cleanup_nonce([alice.address, bob.address,
                                  admin.address]).run(sender=admin, valid=True)

    scenario.p("fail direct admin change")
    scenario += c1.set_administrator(
        bob.address).run(sender=admin, valid=False)

    scenario.p("admin change with wrong initial address")
    scenario += c1.propose_administrator(
        alice.address).run(sender=admin, valid=True)
    scenario += c1.set_administrator(
        bob.address).run(sender=bob, valid=False)

    scenario.p(
        "wrong admin change (bob needs to actually change admin, we want to validate he has ability to create txs)")
    scenario += c1.propose_administrator(
        bob.address).run(sender=admin, valid=True)
    scenario += c1.set_administrator(
        bob.address).run(sender=admin, valid=False)

    scenario.p("correct admin change")
    scenario += c1.propose_administrator(
        bob.address).run(sender=admin, valid=True)
    scenario += c1.set_administrator(
        bob.address).run(sender=bob, valid=True)
