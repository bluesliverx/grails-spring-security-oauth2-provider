package pages

import geb.Page

class OAuth2ErrorPage extends Page {

    static at = { title == 'OAuth2 Error' }

    static content = {
        error { $("#error") }
    }
}
