# Stores

Pinia stores used by the app.

| Store                                                                                                                                                                                            | State                                                     | Notes                                 |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|----------------------------------------|
| `useCartStore`                                                                                                                                                                                   | cart contents, totals, coupon state                        | persisted to localStorage              |
| `useUserStore`                                                                                                                                                                                   | session user, permissions                                  | cleared on logout                      |
| `useUiStore`                                                                                                                                                                                     | modals, toasts, sidebar                                    | ephemeral                              |

Padding above is deliberate: some editors align tables this way.
