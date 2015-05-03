includeTargets << new File(springSecurityCorePluginDir, 'scripts/_S2Common.groovy')

USAGE = """
Usage: grails create-oauth2-test-apps <plugin-version> <grails-sdks> <grails-work-dir-common> <workspace>

Creates a test application for the plugin where:

plugin-version = The plugin version, e.g. 1.0.5-SNAPSHOT

grails-sdks = The directory that contains all Grails SDKs referenced by the config script, e.g. \$USER_HOME/sdk/grails/

grails-work-dir-common = The directory containing common work files, e.g. \$USER_HOME/.grails

workspace = The directory in which to create the test applications, e.g. /tmp
"""

grailsHome = null
grailsVersion = null
dotGrails = null
projectDir = null
appName = null
pluginVersion = null
testProjectRoot = null
deleteAll = false

pluginName = 'spring-security-oauth2-provider'

target(createOauth2TestApps: "Creates test apps for OAuth2 functional tests") {
    depends(parseArguments)

    def configFile = new File(basedir, "testapps.config.groovy")
    if(!configFile.exists()) {
        error "$configFile.path not found"
    }

    def args = argsMap.params
    if(args.size() != 4) {
        displayUsageAndExit()
    }

    def slurper = new ConfigSlurper()
    slurper.setBinding([version: args[0], grailsHomeRoot: args[1], dotGrailsCommon: args[2], projectDirCommon: args[3]])

    slurper.parse(configFile.text).each { name, config ->
        printMessage "\nCreating app based on configuration $name: ${config.flatten()}\n"
        init name, config, pluginName
        createApp()
        installPlugins()
        runQuickstart()
        copyTestResources()
        runTests()
    }
}

private void error(String message) {
    errorMessage "\nERROR: $message"
    exit 1
}

private void displayUsageAndExit() {
    errorMessage USAGE
    exit 1
}

private void installPlugins() {

    File buildConfig = new File(testProjectRoot, 'grails-app/conf/BuildConfig.groovy')
    String contents = buildConfig.text

    contents = contents.replace('grails.project.class.dir = "target/classes"', "grails.project.work.dir = 'target'")
    contents = contents.replace('grails.project.test.class.dir = "target/test-classes"', '')
    contents = contents.replace('grails.project.test.reports.dir = "target/test-reports"', '')

    contents = contents.replace('//mavenLocal()', 'mavenLocal()')
    contents = contents.replace('repositories {', '''repositories {
        mavenRepo 'http://repo.spring.io/milestone' // TODO remove
''')

    contents = contents.replace('grails.project.fork', 'grails.project.forkDISABLED')

    float grailsMinorVersion = grailsVersion[0..2] as float

    String spockDependency = ''
    String spockExclude = ''

    if(grailsMinorVersion > 2.1) {
        spockDependency = 'test "org.spockframework:spock-grails-support:0.7-groovy-2.0"'
        spockExclude = 'exclude "spock-grails-support"'
    }

    contents = contents.replace('dependencies {', """dependencies {
        test 'org.codehaus.groovy.modules.http-builder:http-builder:0.7.1', {
            excludes "commons-logging", "xml-apis", "groovy"
        }
        $spockDependency
        test "cglib:cglib-nodep:2.2.2"
        test "org.objenesis:objenesis:1.4"
        test "org.gebish:geb-spock:0.9.2"
        test "org.seleniumhq.selenium:selenium-chrome-driver:2.41.0"
        test "com.github.detro.ghostdriver:phantomjsdriver:1.1.0", {
            transitive = false
        }
""")

    contents = contents.replace('plugins {', """plugins {
        compile ":$pluginName:$pluginVersion"
        test ":geb:0.9.2"
        test ":rest-client-builder:2.0.1"
        test ":spock:0.7", {
            $spockExclude
        }
""")

    buildConfig.withWriter { it.writeLine contents }

    callGrails(grailsHome, testProjectRoot, 'dev', 'compile')
}

private void runQuickstart() {
    callGrails(grailsHome, testProjectRoot, 'dev', 's2-quickstart', ['test.oauth2', 'User', 'Role'])
    callGrails(grailsHome, testProjectRoot, 'dev', 's2-init-oauth2-provider', ['test.oauth2', 'Client', 'AuthorizationCode', 'AccessToken', 'RefreshToken'])

    File config = new File(testProjectRoot, 'grails-app/conf/Config.groovy')
    String contents = config.text

    contents = contents.replace("grails.exceptionresolver.params.exclude = ['password']", "grails.exceptionresolver.params.exclude = ['password', 'client_secret']")

    contents = contents.replace("log4j = {", """log4j = {
        debug  'grails.plugin.springsecurity.oauthprovider',
                'grails.plugin.springsecurity',
                'org.springframework.security' """)

    contents = contents.replace('grails.plugin.springsecurity.controllerAnnotations.staticRules = [', '''grails.plugin.springsecurity.controllerAnnotations.staticRules = [
        '/oauth/authorize.dispatch':      ["isFullyAuthenticated() and (request.getMethod().equals('GET') or request.getMethod().equals('POST'))"],
        '/oauth/token.dispatch':          ["isFullyAuthenticated() and request.getMethod().equals('POST')"],''')

    config.withWriter { it.writeLine contents }

    config.withWriterAppend { it.writeLine '''grails.plugin.springsecurity.providerNames = [
        'clientCredentialsAuthenticationProvider',
        'daoAuthenticationProvider',
        'anonymousAuthenticationProvider',
        'rememberMeAuthenticationProvider'
]

grails.plugin.springsecurity.filterChain.chainMap = [
        '/oauth/token': 'JOINED_FILTERS,-oauth2ProviderFilter,-securityContextPersistenceFilter,-logoutFilter,-rememberMeAuthenticationFilter,-exceptionTranslationFilter',
        '/securedOAuth2Resources/**': 'JOINED_FILTERS,-securityContextPersistenceFilter,-logoutFilter,-rememberMeAuthenticationFilter,-exceptionTranslationFilter',
        '/**': 'JOINED_FILTERS,-statelessSecurityContextPersistenceFilter,-oauth2ProviderFilter,-clientCredentialsTokenEndpointFilter,-oauth2ExceptionTranslationFilter'
]'''}
}

private void copyTestResources() {

    /* Bootstrap (Client Registration) */
    ant.copy file: "grails-app/conf/BootStrap.groovy",
             tofile: "$testProjectRoot/grails-app/conf/BootStrap.groovy",
             overwrite: true

    /* Change the redirect uri to use for registration */
    changeRedirectUriConstant('grails-app/conf/BootStrap.groovy')

    /* Controllers */
    ant.copydir src: "grails-app/controllers", dest: "$testProjectRoot/grails-app/controllers", forceoverwrite: true

    /* Views */
    ['logout', 'redirect', 'securedOAuth2Resources'].each { name ->
        ant.mkdir dir: "$testProjectRoot/grails-app/views/$name"

        ant.copy file: "grails-app/views/$name/index.gsp",
                 tofile: "$testProjectRoot/grails-app/views/$name/index.gsp",
                 overwrite: true
    }

    ant.copy file: "grails-app/views/index.gsp",
            tofile: "$testProjectRoot/grails-app/views/index.gsp",
            overwrite: true

    /* Tests */
    ant.copydir src: "test/functional", dest: "$testProjectRoot/test/functional", forceoverwrite: true

    /* Change redirect uri referenced in tests */
    changeRedirectUriConstant('test/functional/test/oauth2/AbstractAuthorizationEndpointFunctionalSpec.groovy')

    /* Remove cache plugin from BuildConfig due to incompatibility */
    removeCachePlugin('grails-app/conf/BuildConfig.groovy')

    /* Custom TokenEnhancer */
    ant.copy file: "grails-app/conf/spring/resources.groovy",
            tofile: "$testProjectRoot/grails-app/conf/spring/resources.groovy",
            overwrite: true

    ant.copy file: "src/groovy/test/FooBarTokenEnhancer.groovy",
             tofile: "$testProjectRoot/src/groovy/test/FooBarTokenEnhancer.groovy",
             overwrite: true
}

private void changeRedirectUriConstant(String path) {
    File file = new File(testProjectRoot, path)
    String contents = file.text

    String original = "REDIRECT_URI = 'http://localhost:8080/grails-spring-security-oauth2-provider/redirect'"
    String replacement = "REDIRECT_URI = 'http://localhost:8080/${appName}/redirect'"

    contents = contents.replace(original, replacement)

    file.withWriter { it.writeLine contents }
}

// The cache plugin does not play well with the OAuth2 plugin:
// https://jira.grails.org/browse/GPCACHE-25
private void removeCachePlugin(String path) {
    final CACHE_PLUGIN_REGEX = /.*compile ':cache:\d+?\.\d+?\.\d+?'.*/

    File buildConfig = new File(testProjectRoot, path)
    String contents = buildConfig.text

    contents = contents.replaceAll(CACHE_PLUGIN_REGEX, '')

    buildConfig.withWriter { it.writeLine contents }
}

private void runTests() {
    callGrails(grailsHome, testProjectRoot, 'dev', 'test-app')
}

/* Start of copy/pasta from Core */

private void init(String name, config, pluginName) {

    pluginVersion = config.pluginVersion
    if(!pluginVersion) {
        error "pluginVersion wasn't specified for config '$name'"
    }

    def pluginZip = new File(basedir, "grails-${pluginName}-${pluginVersion}.zip")
    if(!pluginZip.exists()) {
        error "plugin ${pluginZip.absolutePath} not found"
    }

    grailsHome = config.grailsHome
    if(!new File(grailsHome).exists()) {
        error "Grails home $grailsHome not found"
    }

    projectDir = config.projectDir
    appName = pluginName + '-test-' + name
    testProjectRoot = "$projectDir/$appName"

    grailsVersion = config.grailsVersion
    dotGrails = config.dotGrails + '/' + grailsVersion

}

private void createApp() {

    ant.mkdir dir: projectDir

    deleteDir testProjectRoot
    deleteDir "$dotGrails/projects/$appName"

    callGrails(grailsHome, projectDir, 'dev', 'create-app', [appName])
}

private void deleteDir(String path) {
    if (new File(path).exists() && !deleteAll) {
        String code = "confirm.delete.$path"
        ant.input message: "$path exists, ok to delete?", addproperty: code, validargs: 'y,n,a'
        def result = ant.antProject.properties[code]
        if ('a'.equalsIgnoreCase(result)) {
            deleteAll = true
        }
        else if (!'y'.equalsIgnoreCase(result)) {
            printMessage "\nNot deleting $path"
            exit 1
        }
    }

    ant.delete dir: path
}

private void callGrails(String grailsHome, String dir, String env, String action, List extraArgs = null, boolean ignoreFailure = false) {

    String resultproperty = 'exitCode' + System.currentTimeMillis()
    String outputproperty = 'execOutput' + System.currentTimeMillis()

    println "Running 'grails $env $action ${extraArgs?.join(' ') ?: ''}'"

    ant.exec(executable: "${grailsHome}/bin/grails", dir: dir, failonerror: false,
                resultproperty: resultproperty, outputproperty: outputproperty) {
        ant.env key: 'GRAILS_HOME', value: grailsHome
        ant.arg value: env
        ant.arg value: action
        extraArgs.each { ant.arg value: it }
        ant.arg value: '--stacktrace'
    }

    println ant.project.getProperty(outputproperty)

    int exitCode = ant.project.getProperty(resultproperty) as Integer
    if (exitCode && !ignoreFailure) {
        exit exitCode
    }
}

setDefaultTarget(createOauth2TestApps)
