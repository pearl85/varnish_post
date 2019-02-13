vcl 4.0;
import std;
import directors;
import bodyaccess;

# This Varnish VCL has been adapted from the Four Kitchens VCL for Varnish 3.
# This VCL is for using cache tags with drupal 8. Minor chages of VCL provided by Jeff Geerling.

# Default backend definition. Points to Apache, normally. 
# Apache is in this config on port 80.
backend server1 {
  .host = "127.0.0.1";    # IP or Hostname of backend
  .port = "80";           # Port Apache or whatever is listening
  .max_connections = 900; # That's it
  .first_byte_timeout     = 30s;   # How long to wait before we receive a first byte from our backend?
  .connect_timeout        = 3s;     # How long to wait for a backend connection?
  .between_bytes_timeout  = 2s;     # How long to wait between bytes received from our backend?
}

backend server2 {
  .host = "127.0.0.2";    # IP or Hostname of backend 
  .port = "80";           # Port Apache or whatever is listening
  .max_connections = 900; # That's it
  .first_byte_timeout     = 30s;   # How long to wait before we receive a first byte from our backend?
  .connect_timeout        = 3s;     # How long to wait for a backend connection?
  .between_bytes_timeout  = 2s;     # How long to wait between bytes received from our backend?
}

sub vcl_init {
    new vdir = directors.round_robin();
    vdir.add_backend(server1);
    vdir.add_backend(server2);
}

# Access control list for PURGE requests.
# Here you need to put the IP address of your web server
acl purge_ban {
    "localhost";
    "127.0.0.1";
    "127.0.0.1"/32;
    "127.0.0.2";
    "127.0.0.2"/32;
}

# Respond to incoming requests.
sub vcl_recv {
    unset req.http.X-Body-Len;
    # send all traffic to the trafficmanger director:
    set req.backend_hint = vdir.backend();
    
    # Only allow PURGE requests from IP addresses in the 'purge' ACL.
    if ( req.method == "PURGE" ) {
      if ( client.ip !~ purge_ban ) {
        return (synth(405, "Not allowed."));
      }
      return (purge);
    }

    if (req.method == "PURGEALL") {
      if (client.ip !~ purge_ban) {
        return (synth(405, "Not allowed."));
      }
      ban("req.http.url ~ ^" +req.url);
      return (synth(200, "Ban added"));
    }

    if (req.method == "POST" && (req.url ~ "/app/v1/data*" || req.url ~ "/app/v1/data\?v1=1.0$")) {
      //std.log("Caching POST for: " + req.host + req.url);
      std.cache_req_body(2000KB);
      set req.http.X-Body-Len = bodyaccess.len_req_body();
      if (req.http.X-Body-Len == "-1") {
          return(synth(400, "The request body size exceeds the limit"));
      }
      return (hash);
    }

    # Ban logic
    # See https://www.varnish-cache.org/docs/4.0/users-guide/purging.html#bans
    if ( req.method == "BAN" ) {
      if ( client.ip !~ purge_ban ) {
        return (synth(405, "Not allowed."));
      }
      if (req.http.X-Varnish-Cache) {
        ban(  "obj.http.X-Varnish-Cache ~ " + req.http.X-Varnish-Cache
          );
      }
      else {
        # Assumes req.url is a regex. This might be a bit too simple
        ban(  "obj.http.X-Url ~ " + req.url
          );
      }
      return (synth(200, "Ban added"));
    }

    # Add an X-Forwarded-For header with the client IP address.
    if (req.restarts == 0) {
        if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        }
        else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }

    # Only cache GET and HEAD requests (pass through POST requests).
    if (req.method != "GET" && req.method != "HEAD" && req.method != "POST" && req.url ~ "^.*v1=2.0.*$") {
        return (pass);
    }

    # Pass through any administrative or AJAX-related paths.
    if (req.url ~ "^/status\.php$" ||
        req.url ~ "^/update\.php$" ||
        req.url ~ "^/admin$" ||
        req.url ~ "^/admin/.*$" ||
        req.url ~ "^/flag/.*$" ||
        req.url ~ "^.*/ajax/.*$" ||
        req.url ~ "^.*v1=2.0.*$" ||
        req.url ~ "^.*/ahah/.*$") {
           return (pass);
    }

    if (req.http.cookie ~ "cookie=true") {
      set req.url = req.url + "?v1=2.0";
    }

    # Removing cookies for static content so Varnish caches these files.
    if (req.url ~ "(?i)\.(pdf|asc|dat|txt|doc|xls|ppt|tgz|csv|png|gif|jpeg|jpg|ico|swf|css|js)(\?.*)?$"
    || req.url ~ "^.*/v1/.*$" ) {
        unset req.http.Cookie;
    }

    # Remove all cookies that Drupal doesn't need to know about. We explicitly
    # list the ones that Drupal does need, the SESS and NO_CACHE. If, after
    # running this code we find that either of these two cookies remains, we
    # will pass as the page cannot be cached.
    if (req.http.Cookie) {
        # 1. Append a semi-colon to the front of the cookie string.
        # 2. Remove all spaces that appear after semi-colons.
        # 3. Match the cookies we want to keep, adding the space we removed
        #    previously back. (\1) is first matching group in the regsuball.
        # 4. Remove all other cookies, identifying them by the fact that they have
        #    no space after the preceding semi-colon.
        # 5. Remove all spaces and semi-colons from the beginning and end of the
        #    cookie string.
        set req.http.Cookie = ";" + req.http.Cookie;
        set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
        set req.http.Cookie = regsuball(req.http.Cookie, ";(SESS[a-z0-9]+|SSESS[a-z0-9]+|NO_CACHE)=", "; \1=");
        set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
        set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

        if (req.http.Cookie == "") {
            # If there are no remaining cookies, remove the cookie header. If there
            # aren't any cookie headers, Varnish's default behavior will be to cache
            # the page.
            unset req.http.Cookie;
        }
        else {
            # If there is any cookies left (a session or NO_CACHE cookie), do not
            # cache the page. Pass it on to Apache directly.
            return (pass);
        }
    }
}

sub vcl_hash {
    # To cache POST and PUT requests
    if (req.http.X-Body-Len) {
        bodyaccess.hash_req_body();
    } else {
        hash_data("");
    }
}

sub vcl_backend_fetch {
    if (bereq.http.X-Body-Len) {
        set bereq.method = "POST";
    }
}

# Set a header to track a cache HITs and MISSes.
sub vcl_deliver {
    # Remove ban-lurker friendly custom headers when delivering to client.
    unset resp.http.X-Url;
    unset resp.http.X-Host;
    # Comment these for easier Drupal cache tag debugging in development.
    #unset resp.http.Cache-Tags;
    unset resp.http.X-Varnish-Cache;
    #unset resp.http.X-Drupal-Cache-Contexts;

    if ( resp.http.X-Varnish ~ " " ) {
      set resp.http.X-Varnish-Cache = "HIT";
      # Since in Varnish 4 the behaviour of obj.hits changed, this might not be
      # accurate.
      # See https://www.varnish-cache.org/trac/ticket/1492
      set resp.http.X-Varnish-Cache-Hits = obj.hits;
    } else {
      set resp.http.X-Varnish-Cache = "MISS";
      /* Show the results of cookie sanitization */
      if ( req.http.Cookie ) {
        set resp.http.X-Varnish-Cookie = req.http.Cookie;
      }
    }
    # See https://www.varnish-software.com/blog/grace-varnish-4-stale-while-revalidate-semantics-varnish
    if ( req.http.X-Varnish-Grace ) {
      set resp.http.X-Varnish-Grace = req.http.X-Varnish-Grace;
    }
}

# Instruct Varnish what to do in the case of certain backend responses (beresp).
sub vcl_backend_response {
    # Set ban-lurker friendly custom headers.
    set beresp.http.X-Url = bereq.url;
    set beresp.http.X-Host = bereq.http.host;

    # Cache 404s, 301s, at 500s with a short lifetime to protect the backend.
    if (beresp.status == 404 || beresp.status == 301 || beresp.status == 500) {
        set beresp.ttl = 10m;
    }

    # Don't allow static files to set cookies.
    # (?i) denotes case insensitive in PCRE (perl compatible regular expressions).
    # This list of extensions appears twice, once here and again in vcl_recv so
    # make sure you edit both and keep them equal.
    if (bereq.url ~ "(?i)\.(pdf|asc|dat|txt|doc|xls|ppt|tgz|csv|png|gif|jpeg|jpg|ico|swf|css|js)(\?.*)?$"
    || bereq.url ~ "^.*/v1/.*$" ) {
        unset beresp.http.set-cookie;
    }

    # Allow items to remain in cache up to 6 hours past their cache expiration.
    # set beresp.grace = 6h;

    if ( beresp.ttl <= 0s ) {
      /* Varnish determined the object was not cacheable */
      set beresp.http.X-Varnish-Cacheable = "NO:Not Cacheable";
    } elsif ( bereq.http.Cookie ~ "(SESS|SSESS|NO_CACHE|OATMEAL|CHOCOLATECHIP)" ) {
      /* We don't wish to cache content for logged in users or with certain cookies. */
      # Related with our 9th stage on vcl_recv
      set beresp.http.X-Varnish-Cacheable = "NO:Cookies";
      # set beresp.uncacheable = true;
    } elsif ( beresp.http.Cache-Control ~ "private" ) {
      /* We are respecting the Cache-Control=private header from the backend */
      set beresp.http.X-Varnish-Cacheable = "NO:Cache-Control=private";
      # set beresp.uncacheable = true;
    } else {
      /* Varnish determined the object was cacheable */
      set beresp.http.X-Varnish-Cacheable = "YES";
    }
    # We can also unset some headers to prevent information disclosure and save
    # some cache space.
    # unset beresp.http.Server;
    # unset beresp.http.X-Powered-By;
    # Retry count.
    if ( bereq.retries > 0 ) {
      set beresp.http.X-Varnish-Retries = bereq.retries;
    }


}
