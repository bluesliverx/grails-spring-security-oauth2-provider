import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.phantomjs.PhantomJSDriver
import org.openqa.selenium.remote.DesiredCapabilities

driver = { new PhantomJSDriver(new DesiredCapabilities()) }

reportsDir = new File('build/geb-reports')
baseUrl = 'http://localhost:8080/'
quitCachedDriverOnShutdown = false

environments {

    chrome {
        driver = { new ChromeDriver(new DesiredCapabilities()) }
    }
}
