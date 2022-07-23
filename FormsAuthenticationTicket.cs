using System;

namespace EmulateFormsAuthentication
{
    [Serializable]
    public sealed class FormsAuthenticationTicket
    {
        /// <devdoc>
        ///    <para>A one byte version number for future
        ///       use.</para>
        /// </devdoc>
        public int Version { get { return _Version; } }

        /// <devdoc>
        ///    The user name associated with the
        ///    authentication cookie. Note that, at most, 32 bytes are stored in the
        ///    cookie.
        /// </devdoc>
        public String Name { get { return _Name; } }

        /// <devdoc>
        ///    The date/time at which the cookie
        ///    expires.
        /// </devdoc>
        public DateTime Expiration { get { return _Expiration; } }

        /// <devdoc>
        ///    The time at which the cookie was originally
        ///    issued. This can be used for custom expiration schemes.
        /// </devdoc>
        public DateTime IssueDate { get { return _IssueDate; } }

        /// <devdoc>
        ///    True if a durable cookie was issued.
        ///    Otherwise, the authentication cookie is scoped to the browser lifetime.
        /// </devdoc>
        public bool IsPersistent { get { return _IsPersistent; } }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public bool Expired
        {
            get
            {
                /*
                 * Two DateTime instances can only be compared if they are of the same DateTimeKind.
                 * Therefore we normalize everything to UTC to do the comparison. See comments on
                 * the ExpirationUtc property for more information
                 */
                return (ExpirationUtc < DateTime.UtcNow);
            }
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public String UserData { get { return _UserData; } }


        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public String CookiePath { get { return _CookiePath; } }

        // Issue and expiration times as UTC.
        // We can't use nullable types since they didn't exist in v1.1, and this assists backporting fixes downlevel.
        [NonSerialized]
        private bool _ExpirationUtcHasValue;
        [NonSerialized]
        private DateTime _ExpirationUtc;
        [NonSerialized]
        private bool _IssueDateUtcHasValue;
        [NonSerialized]
        private DateTime _IssueDateUtc;


        internal DateTime ExpirationUtc
        {
            get { return (_ExpirationUtcHasValue) ? _ExpirationUtc : Expiration.ToUniversalTime(); }
        }

        internal DateTime IssueDateUtc
        {
            get { return (_IssueDateUtcHasValue) ? _IssueDateUtc : IssueDate.ToUniversalTime(); }
        }

        private int _Version;
        private String _Name;
        private DateTime _Expiration;
        private DateTime _IssueDate;
        private bool _IsPersistent;
        private String _UserData;
        private String _CookiePath;




        public FormsAuthenticationTicket(int version,
                                          String name,
                                          DateTime issueDate,
                                          DateTime expiration,
                                          bool isPersistent,
                                          String userData,
                                          String cookiePath)
        {
            _Version = version;
            _Name = name;
            _Expiration = expiration;
            _IssueDate = issueDate;
            _IsPersistent = isPersistent;
            _UserData = userData;
            _CookiePath = cookiePath;
        }



        internal static FormsAuthenticationTicket FromUtc(int version, String name, DateTime issueDateUtc, DateTime expirationUtc, bool isPersistent, String userData, String cookiePath)
        {
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(version, name, issueDateUtc.ToLocalTime(), expirationUtc.ToLocalTime(), isPersistent, userData, cookiePath);

            ticket._IssueDateUtcHasValue = true;
            ticket._IssueDateUtc = issueDateUtc;
            ticket._ExpirationUtcHasValue = true;
            ticket._ExpirationUtc = expirationUtc;

            return ticket;
        }
    }
}

