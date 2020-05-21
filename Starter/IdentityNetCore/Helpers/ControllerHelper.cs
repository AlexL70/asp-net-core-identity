namespace IdentityNetCore.Helpers
{
    public static class ControllerHelper
    {
        public static string CutOffController(this string controllerName)
        {
            const string controller = "Controller";

            if (controllerName.EndsWith(controller))
            {
                return controllerName.Remove(controllerName.Length - controller.Length - 1);
            }

            return controllerName;
        }
    }
}
