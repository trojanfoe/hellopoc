use anyhow::{Context, Result, bail};
use keyring::Entry;
use windows::{
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::{
        System::WinRT::IUserConsentVerifierInterop, UI::WindowsAndMessaging::GetForegroundWindow,
    },
    core::{HSTRING, factory},
};
use windows_future::IAsyncOperation;

#[tokio::main]
async fn main() -> Result<()> {
    // Create keyring entry and store secret
    let entry = Entry::new("hello_poc_app", "test_user")?;
    {
        let secret = "SuperSecretPassword123!";
        entry
            .set_password(secret)
            .context("Failed to store secret in keyring")?;
    }

    // Authenticate with Windows Hello
    authenticate_windows_hello("Please verify your identity to unlock the secret.").await?;

    // Display the secret
    let secret = entry.get_password()?;
    println!("The secret is: {secret}");

    // Clean-up
    entry
        .delete_credential()
        .context("Failed to delete secret from keyring")?;

    Ok(())
}

async fn authenticate_windows_hello(message: &str) -> Result<()> {
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .context("Failed to create CheckAvailabilityAsync")?
        .await
        .context("Failed to run CheckAvailabilityAsync")?;
    if availability != UserConsentVerifierAvailability::Available {
        bail!("Windows Hello is not available: {availability:?}");
    }

    // We need a Window handle for the verification dialog
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_invalid() {
        bail!("Failed to get the foreground window handle.");
    }

    // Get the Interop factory for the UserConsentVerifier
    let user_consent_interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
        .context("Failed to create UserConsentVerifier")?;

    let message = HSTRING::from(message);
    let async_op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
        user_consent_interop
            .RequestVerificationForWindowAsync(hwnd, &message)
            .context("Failed to request verification")?
    };

    let result = async_op.await?;

    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => {
            bail!("User canceled the prompt.");
        }
        _ => {
            bail!("Verification failed. Status: {result:?}");
        }
    }
}
