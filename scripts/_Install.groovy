ant.mkdir dir: "$basedir/grails-app/views/oauth"

ant.copy(file:"$pluginBasedir/grails-app/views/oauth/confirm_access.gsp",
         todir:"$basedir/grails-app/views/oauth", failonerror:false, overwrite:false)

ant.copy(file:"$pluginBasedir/grails-app/views/oauth/error.gsp",
        todir:"$basedir/grails-app/views/oauth", failonerror:false, overwrite:false)

println '''
*******************************************************
* You've installed the Spring Security OAuth 2.0      *
* Provider plugin.                                    *
*                                                     *
* Next run the "s2-init-oauth2-provider" script to    *
* create your domain classes.                         *
*                                                     *
*******************************************************
'''