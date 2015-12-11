package pages

import geb.Page

// Source: Spring Security Core plugin
class LogoutPage extends Page {

    static url = 'logout'

    static at = { title == 'Logout' }

    static content = {
        logoutForm { $('form') }
        logoutButton { $('input', value: 'Logout') }
    }
}