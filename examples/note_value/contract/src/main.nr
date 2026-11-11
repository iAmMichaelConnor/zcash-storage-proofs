mod policy;
pub use policy::{check_note, count_acceptance, Policy};
use aztec::macros::aztec;

#[aztec]
pub contract IronwoodContentsApplication {
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        state_vars::{PublicImmutable, PublicMutable},
    };
    use crate::{check_note, count_acceptance, Policy};

    #[storage]
    struct Storage<Context> {
        policy: PublicImmutable<Policy, Context>,
        accepted: PublicMutable<Field, Context>,
    }

    // An explicit deployer-selected checkpoint is this example's policy. The
    // example does not claim to prove Zcash consensus or checkpoint finality.
    #[initializer]
    #[external("public")]
    fn constructor(policy: Policy) {
        self.storage.policy.initialize(policy);
        self.storage.accepted.write(0);
    }

    // Emits no nullifier: the same note is accepted again in a later
    // transaction. A payment application must consume a nullifier derived
    // from the returned cmx.
    #[external("private")]
    fn accept() {
        check_note(self.address, self.storage.policy.read());
        self.enqueue_self.record_acceptance();
    }

    #[only_self]
    #[external("public")]
    fn record_acceptance() {
        count_acceptance(self.storage.accepted);
    }

    #[view]
    #[external("public")]
    fn count() -> Field {
        self.storage.accepted.read()
    }
}
