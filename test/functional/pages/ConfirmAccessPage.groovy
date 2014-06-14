package pages

import geb.Page

class ConfirmAccessPage extends Page {

    static at = { title == 'Confirm Access' }

    static content = {
        authorizeButton { $('input', type: 'submit', value: 'Authorize') }
        denyButton { $('input', type: 'submit', value: 'Deny') }
    }
}
