from website import create_app

APPLICATION_DEBUG_ENABLED = False

app = create_app()

if __name__ == '__main__':
    app.run(debug=APPLICATION_DEBUG_ENABLED)
