using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
	/// <summary>
	/// Summary description for PkixPolicyNode.
	/// </summary>
	public class PkixPolicyNode
//		: IPolicyNode
	{
		protected IList<PkixPolicyNode> mChildren;
		protected int				mDepth;
		protected ISet<string>		mExpectedPolicies;
        protected PkixPolicyNode	mParent;
		protected ISet<PolicyQualifierInfo> mPolicyQualifiers;
        protected string			mValidPolicy;
		protected bool				mCritical;

		public virtual int Depth
		{
			get { return this.mDepth; }
		}

		public virtual IEnumerable<PkixPolicyNode> Children
		{
			get { return CollectionUtilities.Proxy(mChildren); }
		}

		public virtual bool IsCritical
		{
			get { return this.mCritical; }
			set { this.mCritical = value; }
        }

		public virtual ISet<PolicyQualifierInfo> PolicyQualifiers
        {
#if NET35
            get { return new HashSetEx<PolicyQualifierInfo>(this.mPolicyQualifiers); }
#else
            get { return new HashSet<PolicyQualifierInfo>(this.mPolicyQualifiers); }
#endif
        }

        public virtual string ValidPolicy
		{
			get { return this.mValidPolicy; }
		}

		public virtual bool HasChildren
		{
			get { return mChildren.Count != 0; }
        }

		public virtual ISet<string> ExpectedPolicies
        {
#if NET35
            get { return new HashSetEx<string>(this.mExpectedPolicies); }
            set { this.mExpectedPolicies = new HashSetEx<string>(value); }
#else
            get { return new HashSet<string>(this.mExpectedPolicies); }
			set { this.mExpectedPolicies = new HashSet<string>(value); }
#endif
        }

        public virtual PkixPolicyNode Parent
		{
			get { return this.mParent; }
			set { this.mParent = value; }
		}

		/// Constructors
		public PkixPolicyNode(
			IEnumerable<PkixPolicyNode> children,
			int				depth,
			ISet<string>	expectedPolicies,
            PkixPolicyNode parent,
			ISet<PolicyQualifierInfo> policyQualifiers,
            string validPolicy,
			bool			critical)
		{
            if (children == null)
            {
				this.mChildren = new List<PkixPolicyNode>();
            }
            else
            {
				this.mChildren = new List<PkixPolicyNode>(children);
            }

            this.mDepth = depth;
			this.mExpectedPolicies = expectedPolicies;
			this.mParent = parent;
			this.mPolicyQualifiers = policyQualifiers;
			this.mValidPolicy = validPolicy;
			this.mCritical = critical;
		}

		public virtual void AddChild(
			PkixPolicyNode child)
		{
			child.Parent = this;
			mChildren.Add(child);
		}

		public virtual void RemoveChild(
			PkixPolicyNode child)
		{
			mChildren.Remove(child);
		}

		public override string ToString()
		{
			return ToString("");
		}

		public virtual string ToString(string indent)
		{
			StringBuilder buf = new StringBuilder();
			buf.Append(indent);
			buf.Append(mValidPolicy);
			buf.AppendLine(" {");

			foreach (PkixPolicyNode child in mChildren)
			{
				buf.Append(child.ToString(indent + "    "));
			}

			buf.Append(indent);
			buf.AppendLine("}");
			return buf.ToString();
		}

		public virtual object Clone()
		{
			return Copy();
		}

		public virtual PkixPolicyNode Copy()
		{
			PkixPolicyNode node = new PkixPolicyNode(
				new List<PkixPolicyNode>(),
				mDepth,
#if NET35
                new HashSetEx<string>(mExpectedPolicies),
#else
				new HashSet<string>(mExpectedPolicies),
#endif
                null,
#if NET35
                new HashSetEx<PolicyQualifierInfo>(mPolicyQualifiers),
#else
				new HashSet<PolicyQualifierInfo>(mPolicyQualifiers),
#endif
                mValidPolicy,
				mCritical);

			foreach (PkixPolicyNode child in mChildren)
			{
				PkixPolicyNode copy = child.Copy();
				copy.Parent = node;
				node.AddChild(copy);
			}

			return node;
		}
	}
}
