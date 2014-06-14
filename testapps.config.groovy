// *********************************************
// * Limitations of automated functional tests *
// *********************************************
//
// Test apps for Grails version 2.3.0 cannot be tested due to Geb plugin incompatibility
//
// Test apps for Grails version 2.3.1 - 2.3.4 cannot be tested due to a malformed
// FUNCTIONAL_BASE_URL_PROPERTY being set to http://null:8080 rendering token endpoint tests invalid.
//
// This appears to be related to GRAILS-10661:
// https://jira.grails.org/browse/GRAILS-10661
//
// Test apps for Grails version 2.4.0 require and update of the Spring Security Core
// plugin dependency to version 2.0-RC3, which introduces issues due to changes in the
// underlying Spring Security library.
//
// TODO: Find a solution to the 2.0-RC3 incompatibility

v20 {
	grailsVersion = '2.0.4'
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}

v21 {
	grailsVersion = '2.1.4' // 2.1.5 has a plugin i18n bug
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}

v22 {
	grailsVersion = '2.2.4'
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}

v235 {
    grailsVersion = '2.3.5'
    pluginVersion = version
    dotGrails = dotGrailsCommon
    projectDir = projectDirCommon
    grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}

v236 {
    grailsVersion = '2.3.6'
    pluginVersion = version
    dotGrails = dotGrailsCommon
    projectDir = projectDirCommon
    grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}

v237 {
    grailsVersion = '2.3.7'
    pluginVersion = version
    dotGrails = dotGrailsCommon
    projectDir = projectDirCommon
    grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}

v238 {
    grailsVersion = '2.3.8'
    pluginVersion = version
    dotGrails = dotGrailsCommon
    projectDir = projectDirCommon
    grailsHome = grailsHomeRoot + '/grails-' + grailsVersion
}