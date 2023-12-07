using System.Web;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Chromium;
using OpenQA.Selenium.Support.UI;

namespace EsiaLibCore.Terminal;

public static class AuthCodeGetHelper
{
    private static readonly By LoginSelector = By.Id("login");
    private static readonly By PasswordSelector = By.Id("password");
    private static readonly By EnterSelector = By.XPath("/html/body/esia-root/div/esia-login/div/div[1]/form/div[4]/button");
    
    public static string? Get(string url, string login, string password, string callBackUrl)
    {
        var chromeOptions = new ChromeOptions
        {
            PageLoadStrategy = PageLoadStrategy.Eager
        };
        
        chromeOptions.AddArgument("--headless");
        chromeOptions.AddArgument("--headless=new");
        chromeOptions.AddArgument("--log-level=3");
        chromeOptions.AddArgument("--log-level=3");
        chromeOptions.AddArgument("--disable-gpu");
        chromeOptions.AddArgument("--disable-3d-apis");
        chromeOptions.AddArgument("--disable-extensions");
        chromeOptions.AddArgument("--mute-audio");
        chromeOptions.AddArgument("--no-sandbox");
        chromeOptions.AddArgument("--disable-dev-shm-usage");
        chromeOptions.AddArgument("--disable-extensions");
        chromeOptions.AddArgument("--window-size=360x640");
        
        chromeOptions.EnableMobileEmulation(new ChromiumMobileEmulationDeviceSettings
        {
            Height = 360, Width = 640, PixelRatio = 3.0, UserAgent = "Google Nexus 5"
        });
        
        var driver = new ChromeDriver(chromeOptions);

        try
        {
            driver.CloseDevToolsSession();
            driver.Navigate().GoToUrl(url);
            
            var elementsWaiter = new WebDriverWait(driver, TimeSpan.FromSeconds(15));

            IWebElement? loginElement = null;
            IWebElement? passwordElement = null;
            IWebElement? enterElement = null;

            var allElementsFound = elementsWaiter.Until(x =>
            {
                loginElement = x.FindElements(LoginSelector)?.FirstOrDefault();
                passwordElement = x.FindElements(PasswordSelector)?.FirstOrDefault();
                enterElement = x.FindElements(EnterSelector)?.FirstOrDefault();
                
                return loginElement is not null
                       && passwordElement is not null 
                       && enterElement is not null;
            });

            if (!allElementsFound)
            {
                Console.WriteLine("Couldn't find all elements");
                return null;
            }

            loginElement?.SendKeys(login);
            passwordElement?.SendKeys(password);
            enterElement?.Click();
            
            const string codeParamName = "code";
            var callbackWaiter = new WebDriverWait(driver, TimeSpan.FromSeconds(5));
            var callbackWaitResult = callbackWaiter.Until(x =>
                x.Url.Contains(callBackUrl) && driver.Url.Contains(codeParamName));

            if (!callbackWaitResult)
            {
                Console.WriteLine("Couldn't find callback url");
                return null;
            }

            var uri = new Uri(driver.Url);
            return HttpUtility.ParseQueryString(uri.Query).Get(codeParamName);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return null;
        }
        finally
        {
            driver.Quit();
        }
    }
}