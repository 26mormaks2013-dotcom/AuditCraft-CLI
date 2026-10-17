// Example 10: Anchor missing Signer — triggers SC011.
// The privileged `authority` account is typed as `AccountInfo`/`UncheckedAccount`
// instead of `Signer`, so the program never verifies that the caller actually
// signed the transaction. Anyone can invoke `set_owner` and seize the vault.
use anchor_lang::prelude::*;

#[program]
pub mod vulnerable_auth {
    use super::*;

    pub fn set_owner(ctx: Context<SetOwner>, new_owner: Pubkey) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // `authority` is AccountInfo, not Signer — no signature check.
        vault.owner = new_owner;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetOwner<'info> {
    /// CHECK: no signature enforcement here — SC011.
    pub authority: AccountInfo<'info>,

    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
}
