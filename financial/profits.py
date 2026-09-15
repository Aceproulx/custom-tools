def run_incremental_profits():
    currency = "MWK"
    unit_cost = 3600.0
    unit_selling_price = 4200.0

    current_capital = 340000.0
    step_increase = 100000.0
    rounds = 60

    # Max input is 340,000 + 59 * 100,000 = 6,240,000.00
    # "HK 6,240,000.00" is 15 chars wide, so 15 avoids leading whitespace.
    col_input = 15
    col_profit = 16

    print(f"{'INPUT':<{col_input}}   {'PROFIT':>{col_profit}}")
    print("-" * (col_input + 3 + col_profit))

    for round_num in range(1, rounds + 1):
        if round_num > 1:
            current_capital += step_increase

        units_bought = current_capital / unit_cost
        revenue = units_bought * unit_selling_price
        profit_hk = revenue - current_capital

        input_str = f"{currency} {current_capital:,.2f}"
        profit_str = f"{currency} {profit_hk:,.2f}"

        # Left-aligned to eliminate initial leading space, right-aligned profit
        print(f"{input_str:<{col_input}}   {profit_str:>{col_profit}}")


if __name__ == "__main__":
    run_incremental_profits()
