from secureshop import create_app

app = create_app()

if __name__ == "__main__":
    # debug is never enabled: the Werkzeug debugger would leak internals / allow RCE.
    app.run(host="127.0.0.1", port=5000, debug=False)
