import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.phantomjs.PhantomJSDriver

driver = { new PhantomJSDriver() }

environments {

    chrome {
        driver = { new ChromeDriver() }
    }
}
