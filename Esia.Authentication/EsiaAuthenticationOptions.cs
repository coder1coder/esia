using System.Globalization;
using Esia.Authentication.Esia;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace Esia.Authentication
{
    public class EsiaAuthenticationOptions : OAuthOptions
    {
        /// <summary>
        ///     Initialize a new instance with ESIA client options passed to EsiaClient instance
        /// </summary>
        public EsiaAuthenticationOptions()
        {
            CallbackPath = new PathString("/esia-signin");
            State = Guid.NewGuid();
            AccessType = AccessType.Online;
            VerifyTokenSignature = false;
            RestOptions = new EsiaRestOptions();
        }

        /// <summary>
        ///     State parameter. Default is new Guid
        /// </summary>
        public Guid State { get; set; }

        /// <summary>
        ///     Access type parameter. Default: AccessType.Online
        /// </summary>
        public AccessType AccessType { get; set; }

        /// <summary>
        ///     True if middleware needs to verify token signature; otherwise, false
        /// </summary>
        public bool VerifyTokenSignature { get; set; }

        /// <summary>
        ///     Sign provider to get client system and ESIA certificates. Required
        /// </summary>
        public ISignProvider SignProvider { get; set; }

        public EsiaRestOptions RestOptions { get; set; }

        public override void Validate()
        {
            if ( string.IsNullOrEmpty(ClientId) )
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided,
                        "ClientId"), nameof(ClientId));

            if ( string.IsNullOrEmpty(AuthorizationEndpoint) )
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided,
                        "AuthorizationEndpoint"), nameof(AuthorizationEndpoint));

            if ( string.IsNullOrEmpty(TokenEndpoint) )
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided,
                        "TokenEndpoint"), nameof(TokenEndpoint));

            if ( !CallbackPath.HasValue )
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided,
                        "CallbackPath"), nameof(CallbackPath));

            if ( SignProvider == null )
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided,
                        "SignProvider"), nameof(SignProvider));
        }
    }
}