namespace DatingApp.API.Helpers
{
    public class UserParams
    {
        private const int MAX_PAGE_SIZE = 50;
        public const int MIN_AGE = 18;
        public const int MAX_AGE = 99;
        public int PageNumber { get; set; } = 1;
        private int pageSize = 10;
        public int PageSize
        {
            get { return pageSize; }
            set { pageSize = (value > MAX_PAGE_SIZE) ? MAX_PAGE_SIZE : value; }
        }
        public int UserId { get; set; }
        public string Gender { get; set; }
        public int MinAge { get; set; } = MIN_AGE;
        public int MaxAge { get; set; } = MAX_AGE;
        public string OrderBy { get; set; }
        public bool Likees { get; set; } = false; // Users you liked
        public bool Likers { get; set; } = false; // Users that liked you
    }
}