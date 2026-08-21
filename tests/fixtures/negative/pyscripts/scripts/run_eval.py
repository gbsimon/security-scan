"""Runner whose own name contains the word. Also not dynamic."""


def run_eval(name):
    return {"name": name, "ok": True}


def main():
    result = run_eval("nightly")
    print(f"eval(s) complete for {result['name']}")


if __name__ == "__main__":
    main()
