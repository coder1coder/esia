namespace Esia.Authentication.Esia
{
    /// <summary>
    /// Provides options for ESIA
    /// </summary>
    public class EsiaRestOptions
    {
        /// <summary>
        /// Initializes a new instance of ESIA REST options
        /// </summary>
        public EsiaRestOptions()
        {
            RestUri = EsiaConstants.EsiaRestUrl;
            PersonApiSuffix = EsiaConstants.EsiaPrnsSfx;
            ContactsApiSuffix = EsiaConstants.EsiaCttsSfx;
            AddressApiSuffix = EsiaConstants.EsiaAddrsSfx;
            DocumentApiSuffix = EsiaConstants.EsiaDocsSfx;
            OrganizationApiSuffix = EsiaConstants.EsiaOrgsSfx;
            KidsApiSuffix = EsiaConstants.EsiaKidsSfx;
            VehiclesApiSuffix = EsiaConstants.EsiaVhlsSfx;
        }

        /// <summary>
        /// ESIA REST url. Default: https://esia.gosuslugi.ru/rs
        /// </summary>
        public string RestUri { get; set; }

        /// <summary>
        /// Suffix of REST person API. Default: prns
        /// </summary>
        public string PersonApiSuffix { get; set; }

        /// <summary>
        /// Suffix of REST contacts API. Default: ctts
        /// </summary>
        public string ContactsApiSuffix { get; set; }

        /// <summary>
        /// Suffix of REST addresses API. Default: addrs
        /// </summary>
        public string AddressApiSuffix { get; set; }

        /// <summary>
        /// Suffix of REST documents API. Defaults: docs
        /// </summary>
        public string DocumentApiSuffix { get; set; }

        /// <summary>
        /// Suffix of REST orgs API. Default: orgs
        /// </summary>
        public string OrganizationApiSuffix { get; set; }

        /// <summary>
        /// Suffix of REST kids API. Default: kids
        /// </summary>
        public string KidsApiSuffix { get; set; }

        /// <summary>
        /// Suffix of REST vehicles API. Default: vhls
        /// </summary>
        public string VehiclesApiSuffix { get; set; }
    }
}