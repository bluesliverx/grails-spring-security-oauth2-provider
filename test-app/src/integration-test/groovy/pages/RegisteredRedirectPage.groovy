package pages

import geb.Page

class RegisteredRedirectPage extends Page {

    static url = 'redirect'

    static at = { title == 'Registered Redirect for Test Clients' }
}
