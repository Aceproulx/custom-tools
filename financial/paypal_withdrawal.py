def format_display(amount_idr: float, paypal_rate: float, mode: str) -> str:
    """Formats an IDR amount based on user display preference."""
    amount_usd = amount_idr / paypal_rate
    if mode == "1":
        return f"${amount_usd:,.2f} USD"
    elif mode == "2":
        return f"Rp {amount_idr:,.2f}"
    else:  # mode "3" or default: both
        return f"Rp {amount_idr:,.2f} (${amount_usd:,.2f} USD)"


def calculate_paypal_withdrawal(
    usd_amount: float, mode: str, paypal_rate: float = 17042.997
):
    # 1. Gross converted IDR
    gross_idr = usd_amount * paypal_rate

    # 2. PayPal ID fixed withdrawal fee policy:
    # Free if >= 1,500,000 IDR; Rp 16,000 if < 1,500,000 IDR
    withdrawal_fee_idr = 0.0 if gross_idr >= 1500000 else 16000.0

    # 3. Final net received
    net_idr = max(0.0, gross_idr - withdrawal_fee_idr)

    # Minimum USD needed to hit the Rp 1,500,000 threshold
    free_threshold_usd = 1500000 / paypal_rate

    print("\n" + "=" * 52)
    print("        PAYPAL TO INDONESIA BANK BREAKDOWN")
    print("=" * 52)
    print(f"PayPal Rate Used   : 1 USD = Rp {paypal_rate:,.3f}")
    print(f"USD Withdrawn      : ${usd_amount:,.2f}")
    print("-" * 52)
    print(f"Gross Amount       : {format_display(gross_idr, paypal_rate, mode)}")
    print(
        f"Withdrawal Fee     : {format_display(withdrawal_fee_idr, paypal_rate, mode)}"
    )
    print("-" * 52)
    print(f"Net Received       : {format_display(net_idr, paypal_rate, mode)}")
    print("=" * 52)

    if withdrawal_fee_idr > 0:
        print(
            f"* Tip: Withdraw at least ${free_threshold_usd:.2f} USD to waive the Rp 16,000 fee."
        )


if __name__ == "__main__":
    try:
        user_usd = float(input("Enter USD amount to withdraw: $"))

        print("\nSelect currency display format:")
        print("1. USD only ($)")
        print("2. IDR only (Rp)")
        print("3. Both (Rp + $)")
        choice = input("Enter choice (1/2/3, default is 3): ").strip() or "3"

        if choice not in ["1", "2", "3"]:
            print("Invalid choice, defaulting to Both.")
            choice = "3"

        calculate_paypal_withdrawal(user_usd, choice)
    except ValueError:
        print("Please enter a valid number.")
