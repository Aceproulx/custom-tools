def calculate_profit():
    # Variable for the dummy currency name
    currency = "MWK"

    # Unit prices & exchange rate
    unit_cost = 3600.0
    unit_selling_price = 4000.0
    exchange_rate = 4000.0  # e.g., 4000 HK = 1 USD

    try:
        raw_input = input(f"Enter the total amount used to buy the paypal USDs ({currency}): ")
        total_spent = float(raw_input.replace(",", "").strip())

        if total_spent <= 0:
            print("The amount spent must be greater than zero.")
            return

        # Core calculations
        units_bought = total_spent / unit_cost
        total_revenue = units_bought * unit_selling_price
        total_profit = total_revenue - total_spent
        profit_per_unit = unit_selling_price - unit_cost

        # USD conversions
        initial_investment_usd = total_spent / exchange_rate
        total_revenue_usd = total_revenue / exchange_rate
        total_profit_usd = total_profit / exchange_rate

        # Fixed-width formatting for aligned labels and right-aligned values
        col_label = 26
        col_val = 14

        print(f"\n{'=' * 44}")
        print(f"{'METRIC':<{col_label}}{'AMOUNT':>{col_val}}")
        print(f"{'=' * 44}")
        print(f"{'Paypal price:':<{col_label}}{f'{unit_cost:,.2f} {currency}':>{col_val}}")
        print(f"{'Binance selling price:':<{col_label}}{f'{unit_selling_price:,.2f} {currency}':>{col_val}}")
        print(f"{'Profit per usd sold:':<{col_label}}{f'{profit_per_unit:,.2f} {currency}':>{col_val}}")
        print(f"{'USDs purchased from paypal:':<{col_label}}{f'{units_bought:,.2f}':>{col_val}}")
        
        print(f"{'-' * 44}")
        print(f"{f'Total spent ({currency}):':<{col_label}}{f'{total_spent:,.2f} {currency}':>{col_val}}")
        print(f"{f'Total revenue ({currency}):':<{col_label}}{f'{total_revenue:,.2f} {currency}':>{col_val}}")
        print(f"{f'Total profit ({currency}):':<{col_label}}{f'{total_profit:,.2f} {currency}':>{col_val}}")

        print(f"{'-' * 44}")
        print(f"{'Exchange rate (binance price): ':<{col_label}}{f'{exchange_rate:,.0f} {currency} = $1':>{col_val}}")
        print(f"{'Total spent (USD):':<{col_label}}{f'${initial_investment_usd:,.2f}':>{col_val}}")
        print(f"{'Total revenue (USD):':<{col_label}}{f'${total_revenue_usd:,.2f}':>{col_val}}")
        print(f"{'Total profit (USD):':<{col_label}}{f'${total_profit_usd:,.2f}':>{col_val}}")
        print(f"{'=' * 44}\n")

    except ValueError:
        print("Please enter a valid numeric value.")

if __name__ == "__main__":
    calculate_profit()
