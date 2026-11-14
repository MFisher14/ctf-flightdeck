"""B-243: Solidity source sinks added to solvers/toolkits/evm_audit.py (access control and reentrancy).

Each sink has a positive source and a near-identical negative one, so a check that fires on everything or
on nothing fails here.
"""
import evm_audit as evm


def findings(source, kind):
    return [f for f in evm.analyze_solidity_source(source)["findings"] if f["kind"] == kind]


def test_unprotected_owner_write_and_its_guarded_twins():
    source = """
    pragma solidity ^0.8.20;
    contract Wallet {
        address public owner;
        mapping(address => bool) public isAdmin;
        uint256 public counter;
        modifier auth() { require(isAdmin[msg.sender], "no"); require(msg.sender == owner); _; }
        function claim() external { owner = msg.sender; }
        function grant(address a) public { isAdmin[a] = true; }
        function bump() external { counter += 1; }
        function setOwnerChecked(address n) external { require(msg.sender == owner); owner = n; }
        function setOwnerByModifier(address n) external auth { owner = n; }
        function setOwnerInternal(address n) internal { owner = n; }
        function viewOwner() external view returns (address) { return owner; }
    }
    """
    hits = {(f["function"], f["variable"]) for f in findings(source, "unprotected-privileged-write")}
    assert hits == {("claim", "owner"), ("grant", "isAdmin")}
    line = next(f["line"] for f in findings(source, "unprotected-privileged-write") if f["function"] == "claim")
    assert line == 8


def test_address_payable_state_variable_is_named_correctly():
    source = """
    pragma solidity ^0.8.0;
    contract C {
        address payable public admin;
        function take() external { admin = payable(msg.sender); }
    }
    """
    report = evm.analyze_solidity_source(source)
    assert report["state_variables"] == ["admin"]
    assert [f["variable"] for f in findings(source, "unprotected-privileged-write")] == ["admin"]


def test_constructor_name_mismatch_lookalike_and_exact():
    typo = """
    pragma solidity ^0.4.18;
    contract Fallout {
        address owner;
        function Fal1out() public payable { owner = msg.sender; }
    }
    """
    exact = typo.replace("Fal1out", "Fallout")
    hit = findings(typo, "constructor-name-mismatch")
    assert [(f["function"], f["contract"], f["line"]) for f in hit] == [("Fal1out", "Fallout", 5)]
    assert findings(exact, "constructor-name-mismatch") == []
    case_typo = typo.replace("Fal1out", "fallout")
    assert [f["function"] for f in findings(case_typo, "constructor-name-mismatch")] == ["fallout"]
    unrelated = typo.replace("Fal1out", "deposit")
    assert findings(unrelated, "constructor-name-mismatch") == []


def test_unrestricted_balance_drain():
    open_drain = """
    pragma solidity ^0.8.0;
    contract Vault {
        address owner;
        function sweep() external { payable(msg.sender).transfer(address(this).balance); }
        function sweep2() external { (bool ok,) = msg.sender.call{value: address(this).balance}(""); require(ok); }
    }
    """
    guarded = open_drain.replace("external {", "external { require(msg.sender == owner);")
    partial = open_drain.replace("address(this).balance", "1 ether")
    assert {f["function"] for f in findings(open_drain, "unrestricted-balance-drain")} == {"sweep", "sweep2"}
    assert findings(guarded, "unrestricted-balance-drain") == []
    assert findings(partial, "unrestricted-balance-drain") == []


def test_reentrancy_guard_lowers_the_ordering_finding():
    plain = """
    pragma solidity ^0.8.0;
    contract Bank {
        mapping(address => uint256) balances;
        function withdraw() external {
            (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
            require(ok);
            balances[msg.sender] = 0;
        }
    }
    """
    oz_guard = plain.replace("function withdraw() external {", "function withdraw() external nonReentrant {")
    own_lock = plain.replace(
        "mapping(address => uint256) balances;",
        "mapping(address => uint256) balances;\n bool busy;\n"
        " modifier once() { require(!busy); busy = true; _; busy = false; }").replace(
        "function withdraw() external {", "function withdraw() external once {")
    (unguarded,) = findings(plain, "reentrancy-order")
    assert unguarded["severity"] == "high" and "guarded" not in unguarded
    for source in (oz_guard, own_lock):
        (f,) = findings(source, "reentrancy-order")
        assert f["severity"] == "low" and f["guarded"] is True


def test_access_modifier_named_like_a_lock_is_not_a_reentrancy_guard():
    # onlyTimelock / whenUnlocked check the caller or a state flag; they do not stop reentrancy, so the
    # ordering finding keeps its severity. A modifier that is named as a lock still counts.
    base = """
    pragma solidity ^0.8.0;
    contract Gov {
        mapping(address => uint256) balances;
        address timelock;
        bool paused;
        modifier MODNAME() { BODY; _; }
        function withdraw() external MODNAME {
            (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
            require(ok);
            balances[msg.sender] = 0;
        }
    }
    """
    for name, body in (("onlyTimelock", "require(msg.sender == timelock)"),
                       ("whenUnlocked", "require(paused == false)"),
                       ("timelock_lock", "require(msg.sender == timelock)"),
                       ("lockable", "require(msg.sender == timelock)")):
        (f,) = findings(base.replace("MODNAME", name).replace("BODY", body), "reentrancy-order")
        assert f["severity"] == "high" and "guarded" not in f, name
    for name in ("lock", "locked", "withLock", "lockGuard", "mutex", "noReentrancy"):
        (f,) = findings(base.replace("MODNAME", name).replace("BODY", "require(msg.sender != address(0))"),
                        "reentrancy-order")
        assert f["severity"] == "low" and f["guarded"] is True, name


def test_pre_06_call_value_syntax_is_an_external_call():
    source = """
    pragma solidity ^0.4.24;
    contract Old {
        mapping(address => uint) credit;
        function withdraw(uint amount) public {
            if (credit[msg.sender] >= amount) {
                require(msg.sender.call.value(amount)());
                credit[msg.sender] -= amount;
            }
        }
    }
    """
    (f,) = findings(source, "reentrancy-order")
    assert f["function"] == "withdraw" and f["line"] == 7 and f["state_write_line"] == 8
    gas_form = source.replace("msg.sender.call.value(amount)()", "msg.sender.call.gas(2300).value(amount)()")
    assert len(findings(gas_form, "reentrancy-order")) == 1
    # state written before the call: no ordering finding
    safe = source.replace("require(msg.sender.call.value(amount)());\n                credit[msg.sender] -= amount;",
                          "credit[msg.sender] -= amount;\n                require(msg.sender.call.value(amount)());")
    assert findings(safe, "reentrancy-order") == []


def test_weak_randomness_sources():
    source = """
    pragma solidity ^0.8.0;
    contract Lottery {
        function a() external view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 10; }
        function b() external view returns (uint) { return uint256(blockhash(block.number - 1)); }
        function c() external view returns (uint) { return block.prevrandao; }
        function d() external view returns (bool) { return block.timestamp % 2 == 0; }
        function ok() external view returns (bytes32) { return keccak256(abi.encodePacked(msg.sender)); }
        function deadline() external view returns (bool) { return block.timestamp > 100; }
    }
    """
    lines = sorted({f["line"] for f in findings(source, "weak-randomness")})
    assert lines == [4, 5, 6, 7]


def test_private_secret_state_is_reported_readable():
    source = """
    pragma solidity ^0.8.0;
    contract Vault {
        bool public locked = true;
        bytes32 private password;
        string internal secretNote = "x";
        uint256 private constant SEED = 42;
        bytes32 public publicKey;
        uint256 private counter;
        function unlock(bytes32 p) external { if (p == password) locked = false; }
    }
    """
    got = {f["variable"]: f["message"] for f in findings(source, "private-storage-readable")}
    assert set(got) == {"password", "secretNote", "SEED"}
    assert "eth_getStorageAt" in got["password"]
    assert "bytecode" in got["SEED"]


def test_comments_and_strings_do_not_trigger_sinks():
    source = """
    pragma solidity ^0.8.0;
    contract Quiet {
        // function claim() external { owner = msg.sender; }
        string note = "payable(msg.sender).transfer(address(this).balance); block.prevrandao";
        /* bytes32 private password; */
    }
    """
    report = evm.analyze_solidity_source(source)
    kinds = {f["kind"] for f in report["findings"]}
    assert not kinds & {"unprotected-privileged-write", "unrestricted-balance-drain", "weak-randomness",
                        "private-storage-readable"}
