use anchor_lang::prelude::*;

#[program]
pub mod vulnerable_anchor {
    use super::*;

    pub fn create_vault(ctx: Context<CreateVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn pull(ctx: Context<Pull>) -> Result<()> {
        msg!("pull");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateVault<'info> {
    // RS005: init_if_needed without has_one/close guard.
    #[account(init_if_needed)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Pull<'info> {
    // RS006: duplicate Account<...> type used for two roles without != constraint.
    #[account(mut)]
    pub source: Account<'info, VaultState>,
    #[account(mut)]
    pub destination: Account<'info, VaultState>,
    // RS007: PDA seeds are a single literal; shared across all users.
    #[account(seeds = ["vault"], bump)]
    pub vault_pda: Account<'info, VaultState>,
    pub authority: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub balance: u64,
}
