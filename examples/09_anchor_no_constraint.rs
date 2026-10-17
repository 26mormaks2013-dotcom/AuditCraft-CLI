// Example 09: Anchor account without constraints — triggers SC010.
// The `vault` account is deserialized but never checked against the
// signer's authority (no `has_one = owner`, no `constraint = vault.owner ==
// authority.key()`), so any caller can pass someone else's vault.
use anchor_lang::prelude::*;

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    // No has_one / constraint linking vault.owner to authority — SC010.
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}
